# Release v2.0.0 - Build and Verify
English only. CPU first release. GPU optional.

## Build
```sh
# Build output lives in ./target inside the repo
cargo test -p clops-core
go -C workers/go test ./...
cmake -S . -B ./build/headless -G Ninja -DCL_OPS_BUILD_GUI=OFF
cmake --build ./build/headless -j
ctest --test-dir ./build/headless -V
```

GUI build fetches SDL3 and ImGui docking automatically:
```sh
cmake --preset dev
cmake --build build/dev -j
```

## Checksums
```sh
sha256sum build/dev/clops_gui > SHA256SUMS
```

## SBOM
Rust: `cargo metadata --format-version 1 > sbom-rust.json`
Go: `go -C workers/go list -m all > sbom-go.txt`
C++: SDL3 plus ImGui versions pinned in CMakeLists FetchContent.

## First run
Scope defaults to lab-only. Safe Mode ON. Audit log cannot be disabled.
Topbar shows real backend from accel probe. GPU missing shows CPU only honestly.
