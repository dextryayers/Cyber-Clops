package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FuzzResult struct {
	Payload  string `json:"payload"`
	Status   int    `json:"status"`
	Length   int64  `json:"length"`
	TimeMs   int64  `json:"time_ms"`
	Filtered bool   `json:"filtered"`
}

// FuzzURL sniper intruder. template contains one $1$ marker in path or query.
// Each payload replaces the marker. Baseline length filters soft 404 echoes.
func FuzzURL(template string, payloads []string, concurrency int, timeoutMs int) []FuzzResult {
	if concurrency < 1 {
		concurrency = 10
	}
	if concurrency > 2000 {
		concurrency = 2000
	}
	if !strings.Contains(template, "$1$") {
		return nil
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	// Baseline: empty marker response for length filter.
	baseLen := int64(-1)
	if req, err := http.NewRequest("GET", strings.Replace(template, "$1$", "", 1), nil); err == nil {
		req.Header.Set("User-Agent", "Cyber-Clops/2.0")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			baseLen = int64(len(body))
		}
	}

	jobs := make(chan string, len(payloads))
	results := make(chan FuzzResult, len(payloads))
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				url := strings.Replace(template, "$1$", p, 1)
				t0 := time.Now()
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Cyber-Clops/2.0")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				ms := time.Since(t0).Milliseconds()
				status := resp.StatusCode
				resp.Body.Close()
				if status == 429 {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				filtered := status == 404 || (baseLen >= 0 && int64(len(body)) == baseLen && status < 300)
				results <- FuzzResult{Payload: p, Status: status, Length: int64(len(body)), TimeMs: ms, Filtered: filtered}
			}
		}()
	}
	for _, p := range payloads {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)
	var out []FuzzResult
	for r := range results {
		out = append(out, r)
	}
	return out
}
