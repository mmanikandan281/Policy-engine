package eval

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/gobwas/glob"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"example.com/jit-engine/internal/model"
)

type programEntry struct{ prog cel.Program }

type EvalEngine struct {
	db         *gorm.DB
	env        *cel.Env
	cache      sync.Map
	failClosed bool
}

func NewEvalEngine(db *gorm.DB, failClosed bool) (*EvalEngine, error) {
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewConst("subject", decls.NewMapType(decls.String, decls.Dyn), nil),
			decls.NewConst("resource", decls.String, nil),
			decls.NewConst("action", decls.String, nil),
			decls.NewConst("metadata", decls.NewMapType(decls.String, decls.Dyn), nil),
			decls.NewConst("protocol", decls.String, nil),
			decls.NewConst("platform", decls.String, nil),
			decls.NewConst("cloud", decls.String, nil),
		),
	)
	if err != nil {
		return nil, err
	}
	return &EvalEngine{db: db, env: env, failClosed: failClosed}, nil
}

func (e *EvalEngine) compileOrGet(id uuid.UUID, expr string) (cel.Program, error) {
	if v, ok := e.cache.Load(id); ok {
		return v.(programEntry).prog, nil
	}
	ast, iss := e.env.Parse(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	checked, iss := e.env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	prog, err := e.env.Program(checked)
	if err != nil {
		return nil, err
	}
	e.cache.Store(id, programEntry{prog: prog})
	return prog, nil
}

type Request struct {
	Subject  map[string]any `json:"subject"`
	Resource string         `json:"resource"`
	Action   string         `json:"action"`
	Metadata map[string]any `json:"metadata"`
	Protocol string         `json:"protocol,omitempty"`
	Platform string         `json:"platform,omitempty"`
	Cloud    string         `json:"cloud,omitempty"`
}

type TraceItem struct {
	PolicyID uuid.UUID `json:"policy_id"`
	Result   *bool     `json:"result,omitempty"`
	Effect   string    `json:"effect"`
	Reason   string    `json:"reason,omitempty"`
	Error    string    `json:"error,omitempty"`
}

func (e *EvalEngine) EvaluateAndAudit(req Request) (decision string, matched *uuid.UUID, reason string, trace []TraceItem, err error) {
	decision, matched, reason, trace, err = e.evaluate(req)
	_ = e.persistAudit(req, decision, matched, trace)
	return
}

func (e *EvalEngine) evaluate(req Request) (string, *uuid.UUID, string, []TraceItem, error) {
	var traceOut []TraceItem

	// Step 1: Evaluate global policies
	globalPolicies, err := e.loadPolicies("global", req.Action)
	if err != nil {
		if e.failClosed {
			return "deny", nil, "database error: " + err.Error(), nil, err
		}
		return "allow", nil, "database error (fail-open)", nil, err
	}

	for _, p := range globalPolicies {
		if resourceMatch(p.Resource, req.Resource) {
			result, matched, reason, trace, err := e.evaluatePolicy(p, req)
			traceOut = append(traceOut, trace...)
			if err != nil {
				return result, matched, reason, traceOut, err
			}
			if result == "deny" {
				return "deny", matched, reason, traceOut, nil
			}
		}
	}

	// Step 2: If global policies pass, evaluate provider-specific policies
	provider := req.Cloud
	if provider == "" || provider == "none" {
		provider = req.Protocol
	}
	if provider == "" {
		return "deny", nil, "Access denied: no provider specified", traceOut, nil
	}
	providerPolicies, err := e.loadPolicies(provider, req.Action)
	if err != nil {
		if e.failClosed {
			return "deny", nil, "database error: " + err.Error(), traceOut, err
		}
		return "allow", nil, "database error (fail-open)", traceOut, err
	}

	type candidate struct {
		p  model.Policy
		sp int
	}
	var cands []candidate
	for _, p := range providerPolicies {
		if resourceMatch(p.Resource, req.Resource) {
			cands = append(cands, candidate{p: p, sp: computeSpecificity(p.Resource)})
		}
	}

	sort.Slice(cands, func(i, j int) bool {
		if cands[i].p.Priority != cands[j].p.Priority {
			return cands[i].p.Priority < cands[j].p.Priority
		}
		if cands[i].sp != cands[j].sp {
			return cands[i].sp > cands[j].sp
		}
		if !cands[i].p.CreatedAt.Equal(cands[j].p.CreatedAt) {
			return cands[i].p.CreatedAt.Before(cands[j].p.CreatedAt)
		}
		return strings.Compare(cands[i].p.ID.String(), cands[j].p.ID.String()) < 0
	})

	var allowWinner *model.Policy
	for _, c := range cands {
		p := c.p
		result, matched, reason, trace, err := e.evaluatePolicy(p, req)
		traceOut = append(traceOut, trace...)
		if err != nil {
			return result, matched, reason, traceOut, err
		}
		if result == "deny" {
			return "deny", matched, reason, traceOut, nil
		}
		if result == "allow" {
			allowWinner = &p
		}
	}

	if allowWinner != nil {
		return "allow", &allowWinner.ID, policyMessageOrDefault(*allowWinner, fmt.Sprintf("Access allowed by policy '%s'", allowWinner.Name)), traceOut, nil
	}
	// Default to deny
	return "deny", nil, fmt.Sprintf("Access denied: no allow policy matched for action '%s' on resource '%s'", req.Action, req.Resource), traceOut, nil
}

// policyMessageOrDefault checks policy.Metadata for key "message" and returns it if present (string), otherwise defaultMsg.
func policyMessageOrDefault(p model.Policy, defaultMsg string) string {
	if len(p.Metadata) > 0 {
		var m map[string]any
		if err := json.Unmarshal(p.Metadata, &m); err == nil {
			if v, ok := m["message"].(string); ok && v != "" {
				return v
			}
		}
	}
	return defaultMsg
}

// policyNonMatchReason provides a user-friendly reason for why a policy did not apply when it evaluated to false.
func policyNonMatchReason(p model.Policy) string {
	// Prefer an optional hint from metadata: { "non_match_message": "Requires subject.group == 'analyst'" }
	if len(p.Metadata) > 0 {
		var m map[string]any
		if err := json.Unmarshal(p.Metadata, &m); err == nil {
			if v, ok := m["non_match_message"].(string); ok && v != "" {
				return v
			}
		}
	}
	return "conditions not met"
}

func (e *EvalEngine) persistAudit(req Request, decision string, matched *uuid.UUID, trace []TraceItem) error {
	rb, _ := json.Marshal(req)
	tb, _ := json.Marshal(trace)
	a := model.PolicyAudit{Request: rb, Decision: decision, MatchedID: matched, Trace: tb}
	return e.db.Create(&a).Error
}

var globCache sync.Map

func resourceMatch(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if g, ok := globCache.Load(pattern); ok {
		return g.(glob.Glob).Match(value)
	}
	g := glob.MustCompile(pattern)
	globCache.Store(pattern, g)
	return g.Match(value)
}

func computeSpecificity(pattern string) int {
	if pattern == "" {
		return 0
	}
	wildcards := 0
	for _, r := range pattern {
		if r == '*' || r == '?' {
			wildcards++
		}
	}
	return len(pattern) - (wildcards * 10)
}

func (e *EvalEngine) loadPolicies(provider, action string) ([]model.Policy, error) {
    var policies []model.Policy

    // Fix the typo: use 'enabled' instead of 'enab led'
    q := e.db.Where("enabled = ? AND provider = ?", true, provider)

    if action != "" {
        q = q.Where("? = ANY(actions) OR array_length(actions,1) IS NULL", action)
    }

    return policies, q.Find(&policies).Error
}


func (e *EvalEngine) evaluatePolicy(p model.Policy, req Request) (string, *uuid.UUID, string, []TraceItem, error) {
	var traceOut []TraceItem
	prog, err := e.compileOrGet(p.ID, p.Expr)
	if err != nil {
		traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Error: "compile: " + err.Error(), Reason: "policy expression failed to compile"})
		if e.failClosed {
			return "deny", &p.ID, fmt.Sprintf("Access denied by policy '%s': expression failed to compile", p.Name), traceOut, nil
		}
		return "allow", nil, "expression failed to compile (fail-open)", traceOut, err
	}
	out, _, evalErr := prog.Eval(map[string]any{
		"subject":  req.Subject,
		"resource": req.Resource,
		"action":   req.Action,
		"metadata": req.Metadata,
		"protocol": req.Protocol,
		"platform": req.Platform,
		"cloud":    req.Cloud,
	})
	if evalErr != nil {
		traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Error: "runtime: " + evalErr.Error(), Reason: "policy evaluation runtime error"})
		if e.failClosed {
			return "deny", &p.ID, fmt.Sprintf("Access denied by policy '%s': runtime error during evaluation", p.Name), traceOut, nil
		}
		return "allow", nil, "runtime error (fail-open)", traceOut, evalErr
	}
	b, ok := out.Value().(bool)
	if !ok {
		traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Error: "non-boolean result", Reason: "policy expression did not return boolean"})
		if e.failClosed {
			return "deny", &p.ID, fmt.Sprintf("Access denied by policy '%s': expression did not return true/false", p.Name), traceOut, nil
		}
		return "allow", nil, "non-boolean result (fail-open)", traceOut, nil
	}
	if b {
		if p.Effect == "deny" {
			r := policyMessageOrDefault(p, fmt.Sprintf("Access denied by policy '%s'", p.Name))
			traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Result: &b, Reason: r})
			return "deny", &p.ID, r, traceOut, nil
		}
		if p.Effect == "allow" {
			r := policyMessageOrDefault(p, fmt.Sprintf("Access allowed by policy '%s'", p.Name))
			traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Result: &b, Reason: r})
			return "allow", &p.ID, r, traceOut, nil
		}
	} else {
		traceOut = append(traceOut, TraceItem{PolicyID: p.ID, Effect: p.Effect, Result: &b, Reason: policyNonMatchReason(p)})
	}
	return "", nil, "", traceOut, nil
}

func (e *EvalEngine) Invalidate(id uuid.UUID) { e.cache.Delete(id) }
func (e *EvalEngine) InvalidateMany(ids []uuid.UUID) {
	for _, id := range ids {
		e.cache.Delete(id)
	}
}
func (e *EvalEngine) InvalidateAll() {
	e.cache.Range(func(k, _ any) bool { e.cache.Delete(k); return true })
}
 