package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStreamLower(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	os.WriteFile(in, []byte("Hello\n\nWORLD\n"), 0644)
	n, err := StreamLower(in, out)
	if err != nil || n != 2 {
		t.Fatalf("expected 2 lines, got %d err %v", n, err)
	}
	body, _ := os.ReadFile(out)
	if string(body) != "hello\nworld\n" {
		t.Fatalf("bad output %q", body)
	}
}
