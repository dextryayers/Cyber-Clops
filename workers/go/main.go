package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	http.HandleFunc("/brute", handleBrute)
	fmt.Println("clops-worker listening on 127.0.0.1:17890")
	_ = http.ListenAndServe("127.0.0.1:17890", nil)
}

func handleBrute(w http.ResponseWriter, r *http.Request) {
	// Phase 0: health only. Full JSON brute endpoint lands in Phase 3.
	// Keeps sidecar contract honest without fake results.
	w.Write([]byte("worker ready, use library Brute in Phase 3"))
	_ = time.Now()
}
