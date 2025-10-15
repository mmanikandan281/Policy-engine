package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"example.com/jit-engine/internal/eval"
	"example.com/jit-engine/internal/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PolicyHandler struct {
	DB     *gorm.DB
	Engine *eval.EvalEngine
}

func (h *PolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Check for provider query parameter and set provider field
	if provider := r.URL.Query().Get("provider"); provider != "" {
		switch provider {
		case "aws", "gcp", "database", "ssh", "rdp", "global":
			p.Provider = provider
		default:
			http.Error(w, "invalid provider", http.StatusBadRequest)
			return
		}
	} else {
		p.Provider = "global"
	}
	p.ID = uuid.Nil
	if err := h.DB.Create(&p).Error; err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if h.Engine != nil {
		h.Engine.Invalidate(p.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(p)
}

func (h *PolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	var ps []model.Policy
	q := h.DB
	if v := r.URL.Query().Get("name"); v != "" {
		q = q.Where("name ILIKE ?", "%"+v+"%")
	}
	if v := r.URL.Query().Get("effect"); v != "" {
		q = q.Where("effect = ?", v)
	}
	if v := r.URL.Query().Get("enabled"); v != "" {
		if v == "true" {
			q = q.Where("enabled = ?", true)
		} else if v == "false" {
			q = q.Where("enabled = ?", false)
		}
	}
	if err := q.Order("priority asc, created_at asc").Find(&ps).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ps)
}

func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := tailID(r.URL.Path, "/policies/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var p model.Policy
	if err := h.DB.First(&p, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (h *PolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := tailID(r.URL.Path, "/policies/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var existing model.Policy
	if err := h.DB.First(&existing, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in model.Policy
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Check for provider query parameter and set provider field
	if provider := r.URL.Query().Get("provider"); provider != "" {
		switch provider {
		case "aws", "gcp", "database", "ssh", "rdp", "global":
			in.Provider = provider
		default:
			http.Error(w, "invalid provider", http.StatusBadRequest)
			return
		}
	}
	in.ID = existing.ID
	// Preserve CreatedAt
	in.CreatedAt = existing.CreatedAt
	if err := h.DB.Model(&existing).Select("name", "effect", "provider", "resource", "actions", "expr", "metadata", "enabled", "priority", "version").Updates(in).Error; err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Refetch the updated policy to get the latest values
	if err := h.DB.First(&existing, "id = ?", existing.ID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.Engine != nil {
		h.Engine.Invalidate(existing.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(existing)
}

func (h *PolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := tailID(r.URL.Path, "/policies/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var p model.Policy
	if err := h.DB.First(&p, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.DB.Delete(&p).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.Engine != nil {
		h.Engine.Invalidate(p.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func tailID(path, prefix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, prefix)
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		return "", false
	}
	return id, true
}

