#!/bin/sh
# Cyber-Clops release check. Fails on any test failure or bad dash.
# Uses PCRE unicode escapes so this file stays clean.
set -e
# Build output lives in ./target inside the repo
echo "[1/4] rust tests"
cargo test -p clops-core --manifest-path core/rust/Cargo.toml
echo "[2/4] go tests"
go -C workers/go test ./...
echo "[3/4] native headless"
cmake -S . -B ./build/headless -G Ninja -DCL_OPS_BUILD_GUI=OFF > /dev/null
cmake --build ./build/headless -j
ctest --test-dir ./build/headless
echo "[4/4] dash guard"
if grep -rnP "\x{2014}|\x{2013}" --exclude-dir=.git --exclude-dir=target .; then
  echo "bad dash found"
  exit 1
fi
echo "release check passed"
