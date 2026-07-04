#!/bin/bash
# run_miri.sh - CI/CD script to execute tests under Miri for memory leak detection

set -e

echo "[*] Initializing cargo miri setup..."
source $HOME/.cargo/env
cargo +nightly miri setup

echo "[*] Running memory safety analysis..."
# We run miri on tests. Miri can be extremely slow, so we isolate to unit tests.
MIRIFLAGS="-Zmiri-symbolic-alignment-check -Zmiri-disable-isolation" cargo +nightly miri test --workspace --lib --tests

echo "[*] Miri memory safety and UB checks passed successfully!"
