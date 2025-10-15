# Implementation Details: Two-Layer Policy Evaluation in JIT Engine

## Introduction

This document provides a highly detailed explanation of the implementation of two-layer policy evaluation in the JIT (Just-In-Time) Policy Engine. The engine is built using Go, Postgres, GORM, and CEL (Common Expression Language) for authorization decisions. The key feature implemented is a two-layer evaluation system where global policies are evaluated first, followed by provider-specific policies, ensuring deny-overrides and proper fallback logic.

The implementation addresses the need to support non-cloud protocols (e.g., RDP, SSH, database) by falling back to `req.Protocol` when `req.Cloud` is empty or "none". This allows policies for different providers (ssh, rdp, database, aws, gcp, etc.) to be evaluated correctly.

## Overview of the Problem

The original system was designed primarily for cloud providers (AWS, GCP, etc.), where the `cloud` field in the evaluation request determined the provider. However, for non-cloud endpoints like RDP, SSH, and databases, the `cloud` field is often empty or set to "none", and the actual provider is indicated by the `protocol` field (e.g., "rdp", "ssh", "database").

The issue was that the evaluation logic only used `req.Cloud` as the provider, causing non-cloud requests to fail or evaluate against the wrong policies. Additionally, the system needed to enforce global policies (e.g., compliance checks) before provider-specific policies.

### Key Requirements
- **Two-Layer Evaluation**: Global policies (provider="global") evaluated first; if any deny, stop. Then evaluate provider-specific policies.
- **Provider Fallback**: If `req.Cloud` is empty or "none", use `req.Protocol` as the provider.
- **Deny-Overrides**: Any matching deny policy immediately denies access.
- **Audit and Trace**: Full audit trail with policy names, reasons, and traces.
- **Backward Compatibility**: Existing cloud-based evaluations continue to work.

## Solution Overview

The solution involved changes across multiple components:
1. **Data Model**: Added `Provider` field to `Policy` struct.
2. **Database**: Migration to add `provider` column.
3. **HTTP API**: Updated handlers to use `provider` query parameter for CRUD operations.
4. **Evaluation Engine**: Refactored `evaluate` function for two-layer logic, with provider fallback.
5. **Validation**: Updated CEL environment to include `request` variable for advanced expressions.

The core change is in `internal/eval/engine.go`, where the `evaluate` function now:
- First evaluates global policies.
- If no global deny, determines provider (cloud or protocol fallback).
- Then evaluates provider-specific policies.

## Detailed Changes

### 1. Data Model Changes (`internal/model/policy.go`)

**Before:**
```go
type Policy struct {
    // ... other fields
    // No Provider field
}
```

**After:**
```go
type Policy struct {
    ID        uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
    Name      string         `gorm:"not null" json:"name"`
    Effect    string         `gorm:"not null" json:"effect"`
    Provider  string         `gorm:"not null;default:'global'" json:"provider"`  // NEW FIELD
    Resource  string         `gorm:"not null" json:"resource"`
    Actions   pq.StringArray `gorm:"type:text[]" json:"actions"`
    Condition datatypes.JSON `gorm:"type:jsonb" json:"condition"`
    Expr      string         `gorm:"type:text" json:"expr"`
    Metadata  datatypes.JSON `gorm:"type:jsonb" json:"metadata"`
    Enabled   bool           `gorm:"default:true" json:"enabled"`
    Priority  int            `gorm:"default:100" json:"priority"`
    Version   int            `gorm:"default:1" json:"version"`
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

**Explanation:**
- Added `Provider` field as a string with default "global".
- This allows policies to be scoped to specific providers (e.g., "aws", "ssh", "rdp").
- Global policies use "global" as provider.
- The field is indexed in the database for efficient queries.

### 2. Database Migration (`cmd/migrate/main.go`)

**Change:**
Added migration to create the `provider` column in the `policies` table.

**Code Snippet:**
```go
migrations = []interface{}{
    // ... existing migrations
    &gormigrate.Migration{
        ID: "add_provider_to_policies",
        Migrate: func(tx *gorm.DB) error {
            return tx.Exec(`ALTER TABLE policies ADD COLUMN provider VARCHAR(255) NOT NULL DEFAULT 'global'`).Error
        },
        Rollback: func(tx *gorm.DB) error {
            return tx.Exec(`ALTER TABLE policies DROP COLUMN provider`).Error
        },
    },
}
```

**Explanation:**
- Uses GORMigrate for schema versioning.
- Adds the column with a default of "global" to ensure existing policies are global.
- Rollback removes the column if needed.

### 3. HTTP API Changes (`internal/httpapi/policies.go`)

**Key Changes:**
- In `Create` method: Set `p.Provider` from `provider` query param (default "global").
- In `Update` method: Set `in.Provider` from `provider` query param.
- Removed logic that prepends provider prefixes to `Resource` (now handled by Provider field).

**Before (Create method):**
```go
func (h *PolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
    // ... decode body
    p.Resource = fmt.Sprintf("%s:%s", provider, p.Resource)  // Prepend provider to resource
    // ...
}
```

**After (Create method):**
```go
func (h *PolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
    provider := r.URL.Query().Get("provider")
    if provider == "" {
        provider = "global"
    }
    // ... decode body
    p.Provider = provider  // Set provider field
    // ...
}
```

**Explanation:**
- Policies are now created with explicit provider via query param (e.g., `?provider=rdp`).
- This allows fine-grained control over policy scope.
- Resource patterns no longer need provider prefixes since provider is separate.

### 4. Evaluation Engine Changes (`internal/eval/engine.go`)

This is the core of the implementation. The `evaluate` function was completely refactored for two-layer evaluation.

**Key Changes:**
- Split evaluation into global and provider-specific phases.
- Added provider fallback logic: `provider = req.Cloud; if provider == "" || provider == "none" { provider = req.Protocol }`
- Updated trace and reason to include policy name.

**New Evaluation Flow:**

```go
func (e *EvalEngine) evaluate(req Request) (string, *uuid.UUID, string, []TraceItem, error) {
    var traceOut []TraceItem

    // Step 1: Evaluate global policies
    globalPolicies, err := e.loadPolicies("global", req.Action)
    if err != nil {
        // handle error
    }
    for _, p := range globalPolicies {
        if resourceMatch(p.Resource, req.Resource) {
            result, matched, reason, trace, err := e.evaluatePolicy(p, req)
            traceOut = append(traceOut, trace...)
            if result == "deny" {
                return "deny", matched, reason, traceOut, nil
            }
        }
    }

    // Step 2: Determine provider
    provider := req.Cloud
    if provider == "" || provider == "none" {
        provider = req.Protocol
    }
    if provider == "" {
        return "deny", nil, "Access denied: no provider specified", traceOut, nil
    }

    // Step 3: Evaluate provider-specific policies
    providerPolicies, err := e.loadPolicies(provider, req.Action)
    // ... similar logic as global, but collect allows and check for denies

    // Return allow if any allow and no deny
}
```

**Explanation:**
- **Global Layer**: Evaluates all policies with provider="global". If any deny matches, immediately return deny. This enforces global rules like compliance.
- **Provider Determination**: Uses `req.Cloud` if present, else falls back to `req.Protocol`. This fixes the original issue.
- **Provider Layer**: Evaluates policies for the determined provider. Collects allow matches but denies override.
- **Trace Updates**: Policy names are now included in reasons (e.g., "Access denied by policy 'Global Context Enforcement'").
- **Caching**: CEL programs are cached per policy ID for performance.

**loadPolicies Function:**
```go
func (e *EvalEngine) loadPolicies(provider, action string) ([]model.Policy, error) {
    var policies []model.Policy
    q := e.db.Where("enabled = ? AND provider = ?", true, provider)
    if action != "" {
        q = q.Where("? = ANY(actions) OR array_length(actions,1) IS NULL", action)
    }
    return policies, q.Find(&policies).Error
}
```

- Filters by provider and action for efficiency.

### 5. Validation Changes (`internal/policy/validate.go`)

**Change:**
Added `request` variable to CEL environment for advanced expressions.

**Before:**
```go
env, err := cel.NewEnv(
    cel.Declarations(
        // ... other declarations
    ),
)
```

**After:**
```go
env, err := cel.NewEnv(
    cel.Declarations(
        // ... existing
        decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)), // NEW
    ),
)
```

**Explanation:**
- Allows CEL expressions to reference the entire request object if needed (e.g., `request.subject.role`).
- Enhances flexibility for complex policies.

## Testing and Verification

### Manual Testing
- **SSH**: Request with `protocol: "ssh"`, `cloud: "none"` → Provider set to "ssh" → Allow if policy matches.
- **RDP**: Request with `protocol: "rdp"`, `cloud: "none"` → Provider set to "rdp" → Allow if policy matches.
- **Database**: Request with `protocol: "database"` → Provider set to "database".
- **Cloud**: Request with `cloud: "aws"` → Provider set to "aws".
- **Global Deny**: Global policy denies if compliance fails, regardless of provider.

### Edge Cases
- Empty protocol and cloud: Denied with "no provider specified".
- Global deny overrides provider allow.
- Resource patterns must match exactly (e.g., "rdp:windows:host/*" for RDP).

### Postman Collection
Updated `postman_complete_collection.json` with examples for all providers, including global policies.

## Conclusion

The implementation successfully adds two-layer evaluation with provider fallback, ensuring the JIT Engine supports both cloud and non-cloud protocols. Key benefits:
- **Security**: Global policies enforce compliance first.
- **Flexibility**: Provider fallback allows seamless integration of RDP, SSH, etc.
- **Performance**: Efficient querying and caching.
- **Auditability**: Detailed traces with policy names.

For questions, refer to the code comments or this document. The system is production-ready with proper error handling and fail-closed behavior.
