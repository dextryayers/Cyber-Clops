package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DirResult struct {
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Length   int64  `json:"length"`
	TimeMs   int64  `json:"time_ms"`
	Redirect string `json:"redirect"`
}

// Calibrate 404 by requesting 3 random tokens. Returns length set and body hash set.
func calibrate404(base string, client *http.Client) (map[int64]bool, map[string]bool) {
	lens := map[int64]bool{}
	hashes := map[string]bool{}
	for i := 0; i < 3; i++ {
		token := fmt.Sprintf("__clops_%d_%d", time.Now().UnixNano(), i)
		url := strings.TrimRight(base, "/") + "/" + token
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Cyber-Clops/2.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		lens[int64(len(body))] = true
		h := md5.Sum(body)
		hashes[hex.EncodeToString(h[:])] = true
	}
	return lens, hashes
}

func isFalsePositive(length int64, bodyHash string, lens map[int64]bool, hashes map[string]bool) bool {
	if lens[length] && hashes[bodyHash] {
		return true
	}
	return false
}

// Brute runs real HTTP fanout with 429 backoff and checkpoint support.
func Brute(base string, words []string, concurrency int, timeoutMs int, startOffset int) []DirResult {
	if concurrency < 1 {
		concurrency = 10
	}
	if concurrency > 5000 {
		concurrency = 5000
	}
	client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	lens, hashes := calibrate404(base, client)

	jobs := make(chan int, len(words))
	results := make(chan DirResult, len(words))
	var wg sync.WaitGroup

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				word := strings.TrimSpace(words[idx])
				if word == "" || strings.HasPrefix(word, "#") {
					continue
				}
				url := strings.TrimRight(base, "/") + "/" + word
				t0 := time.Now()
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", "Cyber-Clops/2.0")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				h := md5.Sum(body)
				bh := hex.EncodeToString(h[:])
				length := int64(len(body))
				status := resp.StatusCode
				redir := resp.Header.Get("Location")
				resp.Body.Close()
				ms := time.Since(t0).Milliseconds()

				if status == 429 {
					time.Sleep(800 * time.Millisecond)
					continue
				}
				if status == 404 {
					continue
				}
				if isFalsePositive(length, bh, lens, hashes) {
					continue
				}
				if status >= 200 && status < 500 {
					results <- DirResult{Path: "/" + word, Status: status, Length: length, TimeMs: ms, Redirect: redir}
				}
			}
		}()
	}
	for i := startOffset; i < len(words); i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(results)

	var out []DirResult
	for r := range results {
		out = append(out, r)
	}
	return out
}
