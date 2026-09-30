package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type bruteReq struct {
	BaseURL     string   `json:"base_url"`
	Words       []string `json:"words"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
	Offset      int      `json:"offset"`
}

type fuzzReq struct {
	Template    string   `json:"template"`
	Payloads    []string `json:"payloads"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func main() {
	addr := "127.0.0.1:17890"
	if v := os.Getenv("CLOPS_WORKER_ADDR"); v != "" {
		addr = v
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	// POST {base_url, words, concurrency, timeout_ms, offset} -> JSON array of DirResult
	http.HandleFunc("/api/brute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var q bruteReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&q); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if q.Concurrency <= 0 {
			q.Concurrency = 20
		}
		if q.TimeoutMs <= 0 {
			q.TimeoutMs = 5000
		}
		writeJSON(w, Brute(q.BaseURL, q.Words, q.Concurrency, q.TimeoutMs, q.Offset))
	})
	// POST {template, payloads, concurrency, timeout_ms} -> JSON array of FuzzResult
	http.HandleFunc("/api/fuzz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var q fuzzReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&q); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if q.Concurrency <= 0 {
			q.Concurrency = 10
		}
		if q.TimeoutMs <= 0 {
			q.TimeoutMs = 5000
		}
		writeJSON(w, FuzzURL(q.Template, q.Payloads, q.Concurrency, q.TimeoutMs))
	})
	fmt.Println("clops-worker listening on " + addr)
	_ = http.ListenAndServe(addr, nil)
}
