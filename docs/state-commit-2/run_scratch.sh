#!/usr/bin/env bash
# STATE-COMMIT-2 scratch reproduction. Safe for a working tree with local edits:
#  - never touches your checkout; builds in a separate git worktree at the tested base commit
#  - no reset/checkout/stash; the worktree is removed at the end
# Usage (MINGW64 bash, from anywhere inside your Qattice clone):
#   git fetch origin docs/state-commit-2-audit
#   git show FETCH_HEAD:docs/state-commit-2/run_scratch.sh > ~/run_scratch.sh && bash ~/run_scratch.sh
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
BASE=baf7345a59a71df53715224c875a9fd7472f9617   # origin/main the results were produced on
BR=refs/remotes/origin/docs/state-commit-2-audit  # branch with the snippets
WT="$ROOT/../sc2-scratch-wt"
OUT="$ROOT/../sc2-scratch-results.txt"
PY=python; command -v py >/dev/null 2>&1 && PY="py -3"

git fetch -q origin main
git fetch -q origin docs/state-commit-2-audit:refs/remotes/origin/docs/state-commit-2-audit
git cat-file -e "$BASE^{commit}" || { echo "base commit $BASE not found; run: git fetch origin main"; exit 1; }
[ -e "$WT" ] && { echo "$WT already exists; remove it first: git worktree remove --force \"$WT\""; exit 1; }
git worktree add -q --detach "$WT" "$BASE"
trap 'git worktree remove --force "$WT" >/dev/null 2>&1 || true' EXIT

D=docs/state-commit-2/scratch-tests
for f in node_tests_a exec_tests node_tests_b; do git show "$BR:$D/$f.rs.txt" > "$WT/$f.snippet"; done

( cd "$WT" && $PY - <<'PY'
def ins_before(path, marker, text):
    s = open(path, newline=None).read()
    assert s.count(marker) == 1, (path, marker[:50])
    i = s.index(marker)
    open(path, 'w', newline='\n').write(s[:i] + text + "\n" + s[i:])
a = open('node_tests_a.snippet').read()
b = open('node_tests_b.snippet').read()
e = open('exec_tests.snippet').read()
n = 'chain-forge-node/src/node.rs'
ins_before(n, '    #[tokio::test]\n    async fn sweep_does_not_restore_validator_with_downgraded_identity', a)
s = open(n, newline=None).read().rstrip()
assert s.endswith('}')
open(n, 'w', newline='\n').write(s[:-1] + b + "}\n")
ins_before('chain-forge-execution/src/lib.rs', '    #[test]\n    fn transfer_tx_succeeds()', e)
PY
)

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$ROOT/target"
: > "$OUT"
cd "$WT"
echo "== executor (overlength) ==" | tee -a "$OUT"
cargo test -j 2 -p chain-forge-execution --lib sc2_scratch -- --nocapture 2>&1 | grep -E "SC2-RESULT|test result|^error" | tee -a "$OUT"
for i in 1 2 3; do
  echo "== node run $i ==" | tee -a "$OUT"
  cargo test -j 2 -p chain-forge-node --bin chain-forge-node sc2_scratch -- --nocapture --test-threads=1 2>&1 \
    | grep -E "SC2-RESULT|test result|^error" | tee -a "$OUT"
done
echo; echo "Results saved to $OUT"
