package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBruteFindsKnownPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("admin panel"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found page body lab"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	words := []string{"admin", "missing123", "login"}
	got := Brute(srv.URL, words, 4, 3000, 0)
	found := map[string]bool{}
	for _, r := range got {
		found[r.Path] = true
	}
	if !found["/admin"] {
		t.Fatalf("expected /admin found, got %+v", got)
	}
	if found["/missing123"] {
		t.Fatalf("false positive on missing path")
	}
}
