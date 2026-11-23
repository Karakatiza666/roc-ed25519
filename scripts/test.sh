#!/bin/bash
# All checks of this package: roc check, roc fmt --check, the L0 test apps
# (tests/*.roc), then each L1 fuzz target (fuzz/*.roc) with a fixed run count
# and seed (TW6), with roc-fuzz 0.7.0. Exit 0 only when all pass.
# Usage: scripts/test.sh [ROC [FUZZ_ROC]]. ROC (default: roc on PATH) runs
# check, fmt and the L0 tests. FUZZ_ROC builds the fuzz targets (default: ROC).
# RUNS=<n> sets the fuzz run count (default 100000). FUZZ_TIME=<s> sets the time
# limit of one fuzz run (default 120). Use the nightly in
# .roc-version.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
ROC=${1:-roc}
FUZZ_ROC=${2:-$ROC}
RUNS=${RUNS:-100000}
# The time limit of one fuzz run in seconds: a run that reaches it ends and passes (roc-fuzz 0.7.0).
FUZZ_TIME=${FUZZ_TIME:-120}
W=$HERE/.work
# No `..` in these paths: roc stops with PathOutsideWorkspace.
export XDG_CACHE_HOME=$W/xdg ROC_CACHE_DIR=$W/xdg/roc
FAIL=0
run() {
	echo "== $*"
	"$@" || { echo "FAILED: $*"; FAIL=1; }
}
cd "$HERE"
"$ROC" version
"$FUZZ_ROC" version
run "$ROC" check package/main.roc
run "$ROC" fmt --check package tests fuzz
for f in tests/*.roc fuzz/*.roc; do run "$ROC" check "$f"; done
for f in tests/*.roc; do run "$ROC" test "$f" --no-cache; done
mkdir -p "$W/fuzz"
for f in fuzz/*.roc; do
	n=$(basename "$f" .roc)
	rm -rf "$W/fuzz/report-$n"
	run "$FUZZ_ROC" build --fuzz "$f" --output="$W/fuzz/$n"
	# roc-fuzz 0.7.0: `run` checks the declared examples, then explores. The report dir must be absent or empty.
	run "$W/fuzz/$n" run --runs="$RUNS" --seed=1 --time="$FUZZ_TIME" --report-dir="$W/fuzz/report-$n"
done
echo
[ $FAIL = 0 ] && echo "ALL PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
