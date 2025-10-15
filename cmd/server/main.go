package main

import (
	"log"
	"net/http"
	"os"

	"example.com/jit-engine/internal/eval"
	"example.com/jit-engine/internal/httpapi"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	godotenv.Load()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	failClosed := true
	if v := os.Getenv("FAIL_CLOSED"); v == "false" || v == "0" {
		failClosed = false
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	eng, err := eval.NewEvalEngine(db, failClosed)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/evaluate", &httpapi.EvalHandler{Engine: eng})
	mux.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		h := &httpapi.PolicyHandler{DB: db, Engine: eng}
		switch r.Method {
		case http.MethodPost:
			h.Create(w, r)
		case http.MethodGet:
			h.List(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/policies/", func(w http.ResponseWriter, r *http.Request) {
		h := &httpapi.PolicyHandler{DB: db, Engine: eng}
		// If the path is exactly "/policies/", treat like collection
		if r.URL.Path == "/policies/" {
			switch r.Method {
			case http.MethodPost:
				h.Create(w, r)
			case http.MethodGet:
				h.List(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		// Else it's expected to be item route
		switch r.Method {
		case http.MethodGet:
			h.Get(w, r)
		case http.MethodPut:
			h.Update(w, r)
		case http.MethodDelete:
			h.Delete(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Service-specific policy creation endpoints

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Println("listening on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
