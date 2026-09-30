package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFuzzSniper(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			w.WriteHeader(404)
			w.Write([]byte("nf"))
			return
		}
		w.Write([]byte("got:" + q))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got := FuzzURL(srv.URL+"/echo?q=$1$", []string{"a", "bb"}, 2, 3000)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	for _, r := range got {
		if r.Filtered {
			t.Fatalf("reflecting payload must not be filtered: %+v", r)
		}
		if !strings.Contains(r.Payload, "a") && r.Payload != "bb" {
			t.Fatalf("bad payload echo: %+v", r)
		}
	}
	if FuzzURL(srv.URL+"/echo?q=nope", []string{"a"}, 1, 1000) != nil {
		t.Fatalf("template without marker must return nil")
	}
}
