package httpapi

import (
	"encoding/json"
	"net/http"

	"example.com/jit-engine/internal/eval"
)

type EvalHandler struct{ Engine *eval.EvalEngine }

func (h *EvalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req eval.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	decision, matched, reason, trace, _ := h.Engine.EvaluateAndAudit(req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"decision": decision,
		"matched":  matched,
		"reason":   reason,
		"trace":    trace,
	})
}
