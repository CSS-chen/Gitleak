# gitleak end-to-end test harness

Python 3.13, standard library only. No third-party packages, no network access
outside loopback HTTP fixture servers.

## Layout

- `tests/fixtures.py` -- builds local git fixture repositories (loose + packed).
- `tests/servers.py` -- HTTP fixture server (static, soft-404 trap, path blocks,
  exact overrides) and helpers.
- `tests/run_e2e.py` -- end-to-end runner: builds `gitleak.exe`, starts the
  fixture servers, runs the real binary (`scan` / `dump` / `auto`) and compares
  restored trees byte-for-byte against the original work tree.
- `tests/E2E_REPORT.md` -- generated after every run: environment, per-scenario
  PASS/FAIL, commands with exit codes, evidence for failures, defects.

## Usage

```
python tests/run_e2e.py                 # build gitleak.exe + run all scenarios
python tests/run_e2e.py --no-build      # reuse an existing gitleak.exe
python tests/run_e2e.py --only packed   # run scenarios whose name matches
python tests/run_e2e.py --list          # list scenario names
python tests/run_e2e.py --keep-tmp      # keep tests/_tmp on exit (debugging)
```

Exit codes: 0 = all scenarios passed, 1 = scenario failure (product defect),
2 = build or fixture failure.

The runner is self-contained: it creates `tests/_tmp/` inside the workspace,
wipes it on start, and removes it on exit unless `--keep-tmp` is given. All
fixture servers bind 127.0.0.1 on ephemeral ports and are shut down in
`finally` blocks (plus an atexit safety net).

## Fixture repositories

Both fixtures are built from the same commit graph, so `HEAD` is identical:

- 3 commits on `main` (`refs/heads/main`), branches `feature`, `feature-wip`.
- 140 tracked files / 204,283 bytes: nested dirs, spaces in names, unicode
  (`中文文件名.txt`), `#` and `%` in a filename, an empty file, a binary file
  with NUL bytes, a ~200 KB binary file and 130 small files for concurrency.
- `remote.origin.url = https://example.com/secret/repo.git`.
- **loose**: normal `.git/objects/XX/...` loose objects.
- **packed**: copied then `git reflog expire --expire=now --all` +
  `git gc --aggressive --prune=now`; all objects live in a single
  `.git/objects/pack/*.pack` and there are zero loose object files.

## Scenarios

| name | what it proves |
|------|----------------|
| version-and-usage | `version` output; usage errors exit 1 |
| A1-scan-loose-target-forms | scan loose repo; target forms `https://...`, `.git/`, `.git/HEAD`, scheme-auto; deterministic slug; JSON fields |
| A2-dump-loose-byte-compare | dump restores all 140 files byte-identically; `--resume`; `--write-git` yields a usable repo (`git status` clean) |
| B1-packed-scan-and-dump | scan + dump when objects are only in a packfile |
| B2-packed-history-writegit | `--history --all-branches --write-git`; restored tree and usable git repo |
| C-no-index-fallback | `.git/index` returns 403 -> dump must fall back to HEAD commit + tree walk |
| D-soft404-trap | every path returns 200 HTML -> scan/dump must not report vulnerable (exit 2) |
| E-fake-head-trap | `.git/HEAD`/`.git/config` return HTML login pages -> not vulnerable |
| F-objects-blocked | `.git/objects/*` returns 403 -> dump fails cleanly (exit 2/3), no panic, no false success |
| G-multi-target-list-and-flags | 4 targets incl. dead port: correct vulnerable count, no hang; `--list` with comments/blank lines; flag smoke tests |
| H-auto-scan-then-dump | `auto` scans then dumps vulnerable targets; all-benign auto exits 2 |
| I-benign-static-site | plain static site without `.git` -> scan/dump exit 2 |

## Byte comparison

`fixtures.snapshot_tree()` walks a directory, hashes every regular file with
sha256 and records its size. `compare_trees()` asserts exact path-set equality
and per-file content equality against the fixture work tree, excluding `.git`.
Windows cannot represent symlinks/exec bits the same way as POSIX git, so the
harness only asserts what the platform actually stores.

## When a scenario fails

The runner never patches the product. Each failure in `tests/E2E_REPORT.md`
carries the exact command line, exit code, stdout/stderr tail, JSON report
extract and request-log notes, so the Go implementation can be fixed and the
suite re-run with `python tests/run_e2e.py`.

## Not covered (by design)

- `--proxy` (no proxy server in this harness) and TLS/https targets.
- The default `./gitleak-out` root: tests always pass an explicit `-o`.
- Interactive/TTY and color behavior (asserted only as "does not crash" via
  `--no-color`).
