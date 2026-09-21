#!/bin/bash -eu
# ClusterFuzzLite build script (AQ-29).
#
# Runs inside the base-builder-rust container (nightly + cargo-fuzz
# preinstalled). `cargo fuzz build -O` instruments and builds EVERY [[bin]]
# in fuzz/Cargo.toml (the same target list fuzz_build_gate.sh compiles
# uninstrumented on stable); each built fuzzer binary is copied into $OUT
# so CFL can pick it up. The loop derives the binary names from the target
# sources, so adding a fuzz target to fuzz/Cargo.toml is enough — no edit
# here. The host triple in the CFL container is x86_64-unknown-linux-gnu.
cd $SRC/rustynet
cargo fuzz build -O
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "$f" .rs)"
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/${target}" "$OUT/"
done
