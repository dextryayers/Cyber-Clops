package main

import (
	"bufio"
	"os"
	"strings"
)

// StreamLower reads input line by line and writes lowercase to output.
// Handles 1 GB plus files without full RAM load. Returns lines written.
func StreamLower(inPath, outPath string) (int, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	w := bufio.NewWriter(out)
	defer w.Flush()
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		w.WriteString(strings.ToLower(line) + "\n")
		n++
	}
	return n, sc.Err()
}
