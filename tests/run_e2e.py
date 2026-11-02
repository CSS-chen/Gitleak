#!/usr/bin/env python3
"""gitleak end-to-end test harness (Python 3.13 stdlib only).

Builds gitleak.exe, builds local git fixture repositories, serves them through
several hostile HTTP fixture servers, then exercises the real binary end to end
(scan / dump / auto) and compares restored trees byte for byte against the
original work tree.

Usage (from the repository root):
    python tests/run_e2e.py                # build + full suite
    python tests/run_e2e.py --no-build     # reuse existing gitleak.exe
    python tests/run_e2e.py --only packed  # run matching scenarios only
    python tests/run_e2e.py --list         # list scenario names
    python tests/run_e2e.py --keep-tmp     # keep tests/_tmp for debugging

Exit codes: 0 all scenarios passed, 1 scenario failure, 2 build/fixture failure.
Writes tests/E2E_REPORT.md with per-scenario PASS/FAIL, evidence and defects.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import fixtures
import servers

TESTS_DIR = Path(__file__).resolve().parent
WORKSPACE = TESTS_DIR.parent
EXE = WORKSPACE / "gitleak.exe"
TMP_ROOT = TESTS_DIR / "_tmp"
REPORT_PATH = TESTS_DIR / "E2E_REPORT.md"

SLUG_RE = re.compile(r".+_[0-9a-f]{8}$")
FENCE = chr(96) * 3

TARGET_KEYS = (
    "input", "root", "vulnerable", "head_ref", "head_commit", "remote",
    "files_restored", "bytes", "out_dir", "missing", "warnings", "error",
)
TOP_KEYS = ("tool", "version", "generated_at", "targets")


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def clip(text, limit=2000):
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + " ...[truncated " + str(len(text) - limit) + " chars]"


def fmt_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_cmd(cmd):
    parts = []
    for arg in cmd:
        arg = str(arg)
        if any(ch in arg for ch in (" ", "\t", '"')):
            parts.append("'" + arg + "'")
        else:
            parts.append(arg)
    return " ".join(parts)


def output_tail(result, limit=1500):
    parts = []
    if result.stdout and result.stdout.strip():
        parts.append("stdout: " + clip(result.stdout, limit))
    if result.stderr and result.stderr.strip():
        parts.append("stderr: " + clip(result.stderr, limit))
    return " || ".join(parts) if parts else "(no output)"


def tool_version(args):
    try:
        cp = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    text = (cp.stdout or "").strip() or (cp.stderr or "").strip()
    return text.splitlines()[0] if text else "unavailable"


def run_git(args, cwd, timeout=120):
    env = os.environ.copy()
    env.update(fixtures._COMMIT_ENV)
    cmd = ["git", "-c", "core.autocrlf=false", "-c", "core.fileMode=false",
           "-c", "core.safecrlf=false", *args]
    try:
        return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        class _TimedOut:
            returncode = -1
            stdout = ""
            stderr = "git command timed out"
        return _TimedOut()


# ---------------------------------------------------------------------------
# results and checks
# ---------------------------------------------------------------------------

class ToolResult:
    def __init__(self, cmd, exit_code, stdout, stderr, timed_out, duration):
        self.cmd = cmd
        self.exit_code = exit_code
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.timed_out = timed_out
        self.duration = duration

    @property
    def combined(self):
        return self.stdout + self.stderr


class ScenarioResult:
    def __init__(self, name):
        self.name = name
        self.status = "PASS"
        self.failures = []
        self.notes = []
        self.evidence = []
        self.duration = 0.0
        self.checks = Checks(self)

    def record(self, result, label=""):
        self.evidence.append(
            "$ " + format_cmd(result.cmd)
            + "  -> exit=" + str(result.exit_code)
            + (" TIMEOUT" if result.timed_out else "")
            + " (%.2fs)" % result.duration
            + (("  [" + label + "]") if label else "")
        )

    def note(self, text):
        self.notes.append(str(text))

    def evidence_line(self, text):
        self.evidence.append(str(text))


class Checks:
    def __init__(self, result):
        self.result = result
        self.expectations = 0

    def expect(self, condition, label, detail=""):
        self.expectations += 1
        if condition:
            return True
        message = label
        if detail:
            message += " | " + str(detail)
        self.result.failures.append(message)
        return False

    def expect_equal(self, actual, expected, label, detail=""):
        extra = "expected=" + repr(expected) + " actual=" + repr(actual)
        if detail:
            extra += " | " + str(detail)
        return self.expect(actual == expected, label, extra)

    def expect_in(self, actual, allowed, label, detail=""):
        extra = "expected one of " + repr(tuple(allowed)) + " actual=" + repr(actual)
        if detail:
            extra += " | " + str(detail)
        return self.expect(actual in allowed, label, extra)

    def note(self, text):
        self.result.note(text)

    def evidence(self, text):
        self.result.evidence_line(text)


# ---------------------------------------------------------------------------
# tool invocation
# ---------------------------------------------------------------------------

# The CLI is Go flag-package style: flags must come BEFORE positional targets
# (gitleak scan [flags] <target>...). Keep scenario call sites readable by
# allowing targets and flags in any order and normalizing here.
VALUE_FLAGS = {
    "-l", "--list", "-o", "--out", "--json", "-c", "--concurrency",
    "--per-host", "--rate", "-t", "--timeout", "--retries", "-A",
    "--user-agent", "-H", "--header", "--proxy", "--threads", "--max-body",
}
BOOL_FLAGS = {
    "-k", "--insecure", "--history", "--all-branches", "--write-git",
    "--resume", "--scan-secrets", "--extra", "--debug", "--quiet", "--no-color",
}


def order_args(args):
    """Move flags (with their values) ahead of positional targets."""
    values = [str(a) for a in args]
    if not values:
        return values
    sub = values[0]
    flags = []
    positionals = []
    index = 1
    while index < len(values):
        token = values[index]
        if token in BOOL_FLAGS:
            flags.append(token)
            index += 1
        elif token in VALUE_FLAGS:
            flags.append(token)
            if index + 1 < len(values):
                flags.append(values[index + 1])
            index += 2
        elif token.startswith("-") and token != "-":
            flags.append(token)
            index += 1
        else:
            positionals.append(token)
            index += 1
    return [sub] + flags + positionals


def run_tool(args, timeout=120, raw=False):
    """Run gitleak. Unless raw=True, hoist flags ahead of positional targets."""
    cmd = [str(EXE)] + ([str(a) for a in args] if raw else order_args(args))
    started = time.monotonic()
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(WORKSPACE),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return ToolResult(cmd, cp.returncode, cp.stdout, cp.stderr, False,
                          time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return ToolResult(cmd, None, out, err, True, time.monotonic() - started)
    except OSError as exc:
        return ToolResult(cmd, None, "", "failed to launch: " + str(exc), False,
                          time.monotonic() - started)


def expect_exit(chk, result, allowed, label, detail_extra=""):
    if isinstance(allowed, int):
        allowed = (allowed,)
    detail = "actual=" + str(result.exit_code)
    if result.timed_out:
        detail += " (TIMED OUT after " + "%.1fs" % result.duration + ")"
    detail += " | " + output_tail(result)
    if detail_extra:
        detail += " | " + detail_extra
    return chk.expect(result.exit_code in allowed, label + ": exit code", detail)


# ---------------------------------------------------------------------------
# JSON report helpers
# ---------------------------------------------------------------------------

def load_report(path, chk, label="report"):
    p = Path(path)
    if not chk.expect(p.is_file(), label + ": JSON file written", "missing " + str(p)):
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        chk.expect(False, label + ": JSON file readable", str(exc))
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        chk.expect(False, label + ": valid JSON", str(exc) + " | head=" + clip(raw, 500))
        return None


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_report(report, chk, label="report"):
    if not chk.expect(isinstance(report, dict), label + ": top-level JSON object"):
        return False
    for key in TOP_KEYS:
        chk.expect(key in report, label + ": top-level key " + key)
    if "tool" in report:
        chk.expect_equal(report.get("tool"), "gitleak", label + ": tool field")
    chk.expect(isinstance(report.get("version"), str) and report.get("version"),
               label + ": version is a non-empty string", repr(report.get("version")))
    generated = report.get("generated_at")
    ts_ok = isinstance(generated, str) and "T" in generated
    if ts_ok:
        try:
            datetime.fromisoformat(generated.replace("Z", "+00:00"))
        except ValueError:
            ts_ok = False
    chk.expect(ts_ok, label + ": generated_at is RFC3339", repr(generated))
    targets = report.get("targets")
    if not chk.expect(isinstance(targets, list), label + ": targets is a list",
                      repr(type(targets))):
        return False
    for index, tgt in enumerate(targets):
        tl = label + ": targets[" + str(index) + "]"
        if not chk.expect(isinstance(tgt, dict), tl + ": is an object"):
            continue
        for key in TARGET_KEYS:
            chk.expect(key in tgt, tl + ": key " + key)
        chk.expect(isinstance(tgt.get("input"), str), tl + ": input is string")
        chk.expect(isinstance(tgt.get("root"), str), tl + ": root is string")
        chk.expect(isinstance(tgt.get("vulnerable"), bool), tl + ": vulnerable is bool",
                   repr(tgt.get("vulnerable")))
        chk.expect(tgt.get("head_ref") is None or isinstance(tgt.get("head_ref"), str),
                   tl + ": head_ref string/null", repr(tgt.get("head_ref")))
        chk.expect(tgt.get("head_commit") is None or isinstance(tgt.get("head_commit"), str),
                   tl + ": head_commit string/null", repr(tgt.get("head_commit")))
        chk.expect(tgt.get("remote") is None or isinstance(tgt.get("remote"), str),
                   tl + ": remote string/null", repr(tgt.get("remote")))
        chk.expect(_is_int(tgt.get("files_restored")), tl + ": files_restored int",
                   repr(tgt.get("files_restored")))
        chk.expect(_is_int(tgt.get("bytes")), tl + ": bytes int", repr(tgt.get("bytes")))
        chk.expect(isinstance(tgt.get("out_dir"), str), tl + ": out_dir string")
        chk.expect(isinstance(tgt.get("missing"), list), tl + ": missing list")
        chk.expect(isinstance(tgt.get("warnings"), list), tl + ": warnings list")
        chk.expect(tgt.get("error") is None or isinstance(tgt.get("error"), str),
                   tl + ": error string/null", repr(tgt.get("error")))
    return True


def find_target(report, needle, chk, label="report"):
    targets = report.get("targets") if isinstance(report, dict) else None
    if not isinstance(targets, list):
        return None
    for tgt in targets:
        if isinstance(tgt, dict) and needle in str(tgt.get("input", "")):
            return tgt
    chk.expect(False, label + ": target entry containing " + repr(needle),
               "inputs=" + repr([t.get("input") for t in targets if isinstance(t, dict)]))
    return None


def resolve_out_dir(tgt):
    raw = tgt.get("out_dir") if isinstance(tgt, dict) else None
    if not raw:
        return None
    path = Path(str(raw))
    if not path.is_absolute():
        path = WORKSPACE / path
    return path


def normalize_ref(value):
    return value.strip() if isinstance(value, str) else ""


def expect_vulnerable(chk, tgt, expected, label):
    if tgt is None:
        return
    chk.expect_equal(tgt.get("vulnerable"), expected,
                     label + ": vulnerable=" + str(expected).lower())


# ---------------------------------------------------------------------------
# tree + git verification
# ---------------------------------------------------------------------------

def compare_trees(expected, out_root, chk, label):
    root = Path(out_root)
    if not chk.expect(root.is_dir(), label + ": restored directory exists", str(root)):
        return
    actual = fixtures.snapshot_tree(root)
    expected_rel = set(expected)
    actual_rel = set(actual)
    missing = sorted(expected_rel - actual_rel)
    extra = sorted(actual_rel - expected_rel)
    differing = sorted(rel for rel in (expected_rel & actual_rel) if expected[rel] != actual[rel])
    chk.expect(not missing, label + ": no missing files",
               "missing=" + str(len(missing)) + " e.g. " + repr(missing[:10]))
    chk.expect(not extra, label + ": no extra files",
               "extra=" + str(len(extra)) + " e.g. " + repr(extra[:10]))
    for rel in differing[:5]:
        chk.expect(False, label + ": bytes identical for " + rel,
                   "expected sha256=%s size=%d actual sha256=%s size=%d"
                   % (expected[rel].get("sha256"), expected[rel].get("size"),
                      actual[rel].get("sha256"), actual[rel].get("size")))
    if len(differing) > 5:
        chk.expect(False, label + ": all files byte-identical",
                   str(len(differing)) + " files differ; first shown above")
    if not missing and not extra and not differing:
        chk.note(label + ": all " + str(len(expected)) + " files restored byte-identically"
                 + " (" + str(sum(v.get("size", 0) for v in expected.values())) + " bytes)")


def check_git_usable(repo, chk, label):
    repo = Path(repo)
    if not chk.expect(repo.is_dir(), label + ": restored directory exists", str(repo)):
        return
    chk.expect((repo / ".git").is_dir(), label + ": .git directory materialized")
    cp = run_git(["status", "--porcelain"], repo)
    if not chk.expect(cp.returncode == 0, label + ": git status runs",
                      "exit=" + str(cp.returncode) + " stderr=" + clip(cp.stderr, 600)):
        return
    chk.expect_equal(cp.stdout.strip(), "", label + ": git status --porcelain clean")
    cp = run_git(["cat-file", "-e", "HEAD"], repo)
    chk.expect_equal(cp.returncode, 0, label + ": git cat-file -e HEAD works",
                     "stderr=" + clip(cp.stderr, 600))
    cp = run_git(["rev-parse", "HEAD"], repo)
    if cp.returncode == 0:
        chk.note(label + ": rebuilt HEAD=" + cp.stdout.strip())
    cp = run_git(["log", "--oneline", "-n", "50"], repo)
    if cp.returncode == 0:
        chk.note(label + ": git log shows " + str(len(cp.stdout.splitlines())) + " commit(s)")
    else:
        chk.note(label + ": git log failed: " + clip(cp.stderr, 400))


def requests_containing(srv, needle):
    return [path for path in srv.request_paths() if needle in path]


# ---------------------------------------------------------------------------
# scenario context + registry
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self, fixture_data):
        self.fixtures = fixture_data
        self.loose = fixture_data["loose"]
        self.packed = fixture_data["packed"]

    def outdir(self, name):
        path = TMP_ROOT / "out" / name
        fixtures._rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def file_path(self, category, name):
        path = TMP_ROOT / category / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


SCENARIOS = []


def scenario(name):
    def decorator(fn):
        SCENARIOS.append((name, fn))
        return fn
    return decorator


def loose_server(ctx, **kwargs):
    kwargs.setdefault("prefix", "/app")
    kwargs.setdefault("name", "loose")
    return servers.FixtureServer(ctx.loose["root"], **kwargs)


def packed_server(ctx, **kwargs):
    kwargs.setdefault("prefix", "/repo")
    kwargs.setdefault("name", "packed")
    return servers.FixtureServer(ctx.packed["root"], **kwargs)


# ===========================================================================
# scenarios
# ===========================================================================

@scenario("version-and-usage")
def scenario_version_and_usage(ctx, res):
    chk = res.checks

    r = run_tool(["version"], timeout=30)
    res.record(r)
    expect_exit(chk, r, 0, "version")
    combined = r.combined.lower()
    chk.expect("gitleak" in combined, "version: output mentions gitleak", clip(r.combined, 400))
    chk.expect(any(ch.isdigit() for ch in combined), "version: output contains a version number")

    r = run_tool(["scan"], timeout=30)
    res.record(r)
    expect_exit(chk, r, 1, "scan with no target (usage error)")

    r = run_tool(["dump"], timeout=30)
    res.record(r)
    expect_exit(chk, r, 1, "dump with no target (usage error)")

    r = run_tool(["definitely-not-a-real-subcommand"], timeout=30)
    res.record(r)
    expect_exit(chk, r, 1, "unknown subcommand (usage error)")

    r = run_tool([], timeout=30)
    res.record(r)
    chk.expect(r.exit_code in (0, 1), "bare invocation: exit 0 or 1",
               "actual=" + str(r.exit_code))
    chk.expect(("usage" in r.combined.lower()) or r.exit_code == 1,
               "bare invocation: prints usage or exits 1", output_tail(r))


@scenario("A1-scan-loose-target-forms")
def scenario_a1_scan(ctx, res):
    chk = res.checks
    first_slug = None
    with loose_server(ctx) as srv:
        url = srv.url()
        out = ctx.outdir("a1-plain")
        j = ctx.file_path("json", "a1-plain.json")
        r = run_tool(["scan", url, "-o", str(out), "--json", str(j),
                      "-c", "8", "--per-host", "4"], timeout=120)
        res.record(r)
        expect_exit(chk, r, 0, "scan plain URL")
        report = load_report(j, chk, "scan report")
        if validate_report(report, chk, "scan report"):
            chk.expect_equal(len(report.get("targets", [])), 1,
                             "scan: exactly one target in report")
            tgt = find_target(report, url, chk, "scan report")
            if tgt is not None:
                expect_vulnerable(chk, tgt, True, "scan plain URL")
                chk.expect_equal(tgt.get("head_commit"), ctx.loose["head_commit"],
                                 "scan: head_commit equals git rev-parse HEAD")
                chk.expect_in(normalize_ref(tgt.get("head_ref")),
                              ("refs/heads/main", "main"), "scan: head_ref is main")
                chk.expect_equal(tgt.get("remote"), ctx.loose["remote_url"],
                                 "scan: remote read from .git/config")
                restored = resolve_out_dir(tgt)
                if restored is None:
                    chk.note("scan report out_dir is empty; slug checks skipped")
                else:
                    first_slug = restored.name
                    chk.expect(bool(SLUG_RE.match(restored.name)),
                               "scan: out_dir basename is <host_port_path>_<8 hex>",
                               restored.name)
                    chk.expect(restored == out or out in restored.parents,
                               "scan: out_dir is under the -o root", str(restored))
                    res.note("scan out_dir basename=" + restored.name)

        # determinism: identical input in a different -o root -> identical slug
        out2 = ctx.outdir("a1-repeat")
        j2 = ctx.file_path("json", "a1-repeat.json")
        r2 = run_tool(["scan", url, "-o", str(out2), "--json", str(j2)], timeout=120)
        res.record(r2)
        expect_exit(chk, r2, 0, "scan repeat (determinism)")
        report2 = load_report(j2, chk, "repeat report")
        if validate_report(report2, chk, "repeat report"):
            tgt2 = find_target(report2, url, chk, "repeat report")
            if tgt2 is not None and first_slug is not None:
                slug2 = resolve_out_dir(tgt2)
                chk.expect(slug2 is not None and slug2.name == first_slug,
                           "scan: slug deterministic across runs",
                           "first=" + str(first_slug) + " second="
                           + (slug2.name if slug2 else "None"))

        # accepted target forms: .git/ and .git/HEAD suffixes
        for form_name, target in ((".git-suffix", url + "/.git/"),
                                  (".git-HEAD-suffix", url + "/.git/HEAD")):
            outx = ctx.outdir("a1-" + form_name)
            jx = ctx.file_path("json", "a1-" + form_name + ".json")
            rx = run_tool(["scan", target, "-o", str(outx), "--json", str(jx)], timeout=120)
            res.record(rx)
            expect_exit(chk, rx, 0, "scan target form " + form_name)
            repx = load_report(jx, chk, form_name + " report")
            if validate_report(repx, chk, form_name + " report"):
                tgx = find_target(repx, "127.0.0.1", chk, form_name + " report")
                if tgx is not None:
                    expect_vulnerable(chk, tgx, True, form_name)
                    chk.expect_equal(tgx.get("head_commit"), ctx.loose["head_commit"],
                                     form_name + ": head_commit still resolved")

        # scheme auto: host/path without scheme
        no_scheme = "127.0.0.1:" + str(srv.port) + "/app"
        outn = ctx.outdir("a1-noscheme")
        jn = ctx.file_path("json", "a1-noscheme.json")
        rn = run_tool(["scan", no_scheme, "-o", str(outn), "--json", str(jn)], timeout=120)
        res.record(rn)
        if expect_exit(chk, rn, 0, "scan host/path (scheme auto)"):
            repn = load_report(jn, chk, "scheme-auto report")
            if validate_report(repn, chk, "scheme-auto report"):
                tgn = find_target(repn, "127.0.0.1", chk, "scheme-auto report")
                if tgn is not None:
                    expect_vulnerable(chk, tgn, True, "scheme auto")
                    chk.expect_equal(tgn.get("head_commit"), ctx.loose["head_commit"],
                                     "scheme auto: head_commit resolved")


@scenario("A2-dump-loose-byte-compare")
def scenario_a2_dump(ctx, res):
    chk = res.checks
    with loose_server(ctx) as srv:
        url = srv.url()

        # plain dump
        out = ctx.outdir("a2-dump")
        j = ctx.file_path("json", "a2-dump.json")
        r = run_tool(["dump", url, "-o", str(out), "--json", str(j)], timeout=180)
        res.record(r)
        expect_exit(chk, r, 0, "dump plain")
        report = load_report(j, chk, "dump report")
        if validate_report(report, chk, "dump report"):
            tgt = find_target(report, url, chk, "dump report")
            if tgt is not None:
                expect_vulnerable(chk, tgt, True, "dump plain")
                chk.expect_equal(tgt.get("head_commit"), ctx.loose["head_commit"],
                                 "dump: head_commit resolved from HEAD")
                chk.expect_in(normalize_ref(tgt.get("head_ref")),
                              ("refs/heads/main", "main"), "dump: head_ref is main")
                chk.expect_equal(tgt.get("remote"), ctx.loose["remote_url"],
                                 "dump: remote read from .git/config")
                restored = resolve_out_dir(tgt)
                chk.expect(restored is not None, "dump: out_dir is set in report")
                if restored is not None:
                    compare_trees(ctx.loose["files"], restored, chk, "loose restore")
                    chk.expect_equal(tgt.get("files_restored"), ctx.loose["file_count"],
                                     "dump: files_restored equals original file count")
                    chk.expect(_is_int(tgt.get("bytes")) and tgt.get("bytes") > 0,
                               "dump: bytes > 0", repr(tgt.get("bytes")))
                    chk.expect_equal(tgt.get("missing"), [], "dump: missing list empty")
                    chk.expect(not (restored / ".git").exists(),
                               "dump: no .git directory without --write-git")

        # flags AFTER the target must also work (CLI reorderArgs regression test)
        out_after = ctx.outdir("a2-flags-last")
        j_after = ctx.file_path("json", "a2-flags-last.json")
        ra = run_tool(["dump", url, "-o", str(out_after), "--json", str(j_after)],
                      timeout=180, raw=True)
        res.record(ra, "flags after target")
        expect_exit(chk, ra, 0, "dump with flags AFTER target (reorderArgs)")
        report_after = load_report(j_after, chk, "flags-last report")
        if validate_report(report_after, chk, "flags-last report"):
            tg_after = find_target(report_after, url, chk, "flags-last report")
            if tg_after is not None:
                r_after = resolve_out_dir(tg_after)
                if r_after is not None:
                    compare_trees(ctx.loose["files"], r_after, chk, "flags-last restore")

        # --resume against a fresh directory must succeed and restore everything
        outr = ctx.outdir("a2-resume")
        jr = ctx.file_path("json", "a2-resume.json")
        rr = run_tool(["dump", url, "-o", str(outr), "--json", str(jr), "--resume"],
                      timeout=180)
        res.record(rr)
        expect_exit(chk, rr, 0, "dump --resume on fresh dir")
        reportr = load_report(jr, chk, "resume report")
        if validate_report(reportr, chk, "resume report"):
            tgr = find_target(reportr, url, chk, "resume report")
            if tgr is not None:
                restored_r = resolve_out_dir(tgr)
                if restored_r is not None:
                    compare_trees(ctx.loose["files"], restored_r, chk, "resume restore")

        # --write-git must materialize a usable repository
        outw = ctx.outdir("a2-writegit")
        jw = ctx.file_path("json", "a2-writegit.json")
        rw = run_tool(["dump", url, "-o", str(outw), "--json", str(jw), "--write-git"],
                      timeout=180)
        res.record(rw)
        expect_exit(chk, rw, 0, "dump --write-git")
        reportw = load_report(jw, chk, "write-git report")
        if validate_report(reportw, chk, "write-git report"):
            tgw = find_target(reportw, url, chk, "write-git report")
            if tgw is not None:
                restored_w = resolve_out_dir(tgw)
                if restored_w is not None:
                    compare_trees(ctx.loose["files"], restored_w, chk, "write-git restore")
                    check_git_usable(restored_w, chk, "write-git")


@scenario("B1-packed-scan-and-dump")
def scenario_b1_packed(ctx, res):
    chk = res.checks
    with packed_server(ctx) as srv:
        url = srv.url()
        out = ctx.outdir("b1-scan")
        j = ctx.file_path("json", "b1-scan.json")
        r = run_tool(["scan", url, "-o", str(out), "--json", str(j)], timeout=120)
        res.record(r)
        expect_exit(chk, r, 0, "scan packed repo")
        report = load_report(j, chk, "packed scan report")
        if validate_report(report, chk, "packed scan report"):
            tgt = find_target(report, url, chk, "packed scan report")
            if tgt is not None:
                expect_vulnerable(chk, tgt, True, "packed scan")
                chk.expect_equal(tgt.get("head_commit"), ctx.packed["head_commit"],
                                 "packed scan: head_commit matches")

        # dump must read HEAD tree objects out of the packfile (loose objects gone)
        outd = ctx.outdir("b1-dump")
        jd = ctx.file_path("json", "b1-dump.json")
        rd = run_tool(["dump", url, "-o", str(outd), "--json", str(jd)], timeout=180)
        res.record(rd)
        expect_exit(chk, rd, 0, "dump packed repo (packfile only)")
        reportd = load_report(jd, chk, "packed dump report")
        if validate_report(reportd, chk, "packed dump report"):
            tgd = find_target(reportd, url, chk, "packed dump report")
            if tgd is not None:
                restored = resolve_out_dir(tgd)
                if restored is not None:
                    compare_trees(ctx.packed["files"], restored, chk, "packed restore")
        res.note("packed fixture: pack files=" + repr(ctx.packed["pack_files"])
                 + " loose_object_files=" + str(ctx.packed.get("loose_object_files")))


@scenario("B2-packed-history-writegit")
def scenario_b2_history(ctx, res):
    chk = res.checks
    with packed_server(ctx) as srv:
        url = srv.url()
        out = ctx.outdir("b2-history")
        j = ctx.file_path("json", "b2-history.json")
        r = run_tool(["dump", url, "-o", str(out), "--json", str(j),
                      "--history", "--all-branches", "--write-git"], timeout=240)
        res.record(r)
        expect_exit(chk, r, 0, "dump --history --all-branches --write-git")
        report = load_report(j, chk, "history report")
        if validate_report(report, chk, "history report"):
            tgt = find_target(report, url, chk, "history report")
            if tgt is not None:
                expect_vulnerable(chk, tgt, True, "history dump")
                restored = resolve_out_dir(tgt)
                if restored is not None:
                    compare_trees(ctx.packed["files"], restored, chk, "history restore")
                    check_git_usable(restored, chk, "history write-git")
                    cp = run_git(["rev-parse", "HEAD"], restored)
                    if cp.returncode == 0 and cp.stdout.strip() != ctx.packed["head_commit"]:
                        res.note("WARN: rebuilt HEAD " + cp.stdout.strip()
                                 + " differs from original " + ctx.packed["head_commit"]
                                 + " (synthetic commit? informational)")
                    elif cp.returncode == 0:
                        res.note("rebuilt HEAD hash preserved: " + cp.stdout.strip())


@scenario("C-no-index-fallback")
def scenario_c_no_index(ctx, res):
    chk = res.checks
    with servers.FixtureServer(ctx.loose["root"], prefix="/app", name="no-index",
                               blocks=[(".git/index", 403)]) as srv:
        url = srv.url()
        outs = ctx.outdir("c-scan")
        js = ctx.file_path("json", "c-scan.json")
        rs = run_tool(["scan", url, "-o", str(outs), "--json", str(js)], timeout=120)
        res.record(rs)
        expect_exit(chk, rs, 0, "scan with .git/index blocked")
        reports = load_report(js, chk, "no-index scan report")
        if validate_report(reports, chk, "no-index scan report"):
            tg = find_target(reports, url, chk, "no-index scan report")
            if tg is not None:
                expect_vulnerable(chk, tg, True, "no-index scan")

        out = ctx.outdir("c-dump")
        j = ctx.file_path("json", "c-dump.json")
        r = run_tool(["dump", url, "-o", str(out), "--json", str(j)], timeout=180)
        res.record(r)
        expect_exit(chk, r, 0, "dump with .git/index blocked (HEAD -> tree fallback)")
        report = load_report(j, chk, "no-index dump report")
        if validate_report(report, chk, "no-index dump report"):
            tgt = find_target(report, url, chk, "no-index dump report")
            if tgt is not None:
                restored = resolve_out_dir(tgt)
                if restored is not None:
                    compare_trees(ctx.loose["files"], restored, chk, "no-index restore")

        blocked = requests_containing(srv, "/.git/index")
        chk.note("fixture served " + str(len(blocked))
                 + " request(s) for .git/index with 403")
        if not blocked:
            chk.note("tool never requested .git/index; fallback path not proven by request log")


@scenario("D-soft404-trap")
def scenario_d_soft404(ctx, res):
    chk = res.checks
    with servers.FixtureServer(ctx.loose["root"], prefix="/app", mode="soft404",
                               name="soft404") as srv:
        url = srv.url()
        outs = ctx.outdir("d-scan")
        js = ctx.file_path("json", "d-scan.json")
        rs = run_tool(["scan", url, "-o", str(outs), "--json", str(js)], timeout=120)
        res.record(rs)
        expect_exit(chk, rs, 2, "soft-404: scan finds nothing")
        reports = load_report(js, chk, "soft-404 scan report")
        if reports is not None and validate_report(reports, chk, "soft-404 scan report"):
            tg = find_target(reports, url, chk, "soft-404 scan report")
            if tg is not None:
                expect_vulnerable(chk, tg, False, "soft-404 scan")

        outs2 = ctx.outdir("d-dump")
        jd = ctx.file_path("json", "d-dump.json")
        rd = run_tool(["dump", url, "-o", str(outs2), "--json", str(jd)], timeout=120)
        res.record(rd)
        expect_exit(chk, rd, 2, "soft-404: dump exits 2 (not vulnerable)")
        res.note("soft-404 fixture returned 200 HTML for every path (trap)")


@scenario("E-fake-head-trap")
def scenario_e_fake_head(ctx, res):
    chk = res.checks
    login = b"<!doctype html><html><head><title>Login</title></head><body>Please login</body></html>"
    generic = b"<!doctype html><html><head><title>Home</title></head><body>generic page</body></html>"
    overrides = {
        ".git/HEAD": (200, "text/html; charset=utf-8", login),
        ".git/config": (200, "text/html; charset=utf-8", generic),
    }
    with servers.FixtureServer(ctx.loose["root"], prefix="/app", name="fake-head",
                               overrides=overrides) as srv:
        url = srv.url()
        outs = ctx.outdir("e-scan")
        js = ctx.file_path("json", "e-scan.json")
        rs = run_tool(["scan", url, "-o", str(outs), "--json", str(js)], timeout=120)
        res.record(rs)
        expect_exit(chk, rs, 2, "fake HEAD: scan finds nothing")
        reports = load_report(js, chk, "fake-head scan report")
        if reports is not None and validate_report(reports, chk, "fake-head scan report"):
            tg = find_target(reports, url, chk, "fake-head scan report")
            if tg is not None:
                expect_vulnerable(chk, tg, False, "fake-head scan")

        outd = ctx.outdir("e-dump")
        jd = ctx.file_path("json", "e-dump.json")
        rd = run_tool(["dump", url, "-o", str(outd), "--json", str(jd)], timeout=120)
        res.record(rd)
        expect_exit(chk, rd, 2, "fake HEAD: dump exits 2 (not vulnerable)")


@scenario("F-objects-blocked")
def scenario_f_objects_blocked(ctx, res):
    chk = res.checks
    with servers.FixtureServer(ctx.loose["root"], prefix="/app", name="objects-blocked",
                               blocks=[(".git/objects/", 403)]) as srv:
        url = srv.url()
        outs = ctx.outdir("f-scan")
        js = ctx.file_path("json", "f-scan.json")
        rs = run_tool(["scan", url, "-o", str(outs), "--json", str(js)], timeout=120)
        res.record(rs)
        chk.expect(not rs.timed_out, "objects-blocked: scan does not hang")
        chk.expect_in(rs.exit_code, (0, 2, 3), "objects-blocked: scan exit code sane",
                      output_tail(rs))
        if rs.exit_code == 2:
            reports = load_report(js, chk, "objects-blocked scan report")
            if reports is not None and validate_report(reports, chk,
                                                       "objects-blocked scan report"):
                tg = find_target(reports, url, chk, "objects-blocked scan report")
                if tg is not None:
                    res.note("objects-blocked scan reported vulnerable="
                             + repr(tg.get("vulnerable")))
        else:
            res.note("objects-blocked scan exit=" + str(rs.exit_code)
                     + " (HEAD is valid, so detection is acceptable)")

        out = ctx.outdir("f-dump")
        j = ctx.file_path("json", "f-dump.json")
        rd = run_tool(["dump", url, "-o", str(out), "--json", str(j)], timeout=120)
        res.record(rd)
        expect_exit(chk, rd, (2, 3), "objects-blocked: dump fails cleanly (exit 2 or 3)")
        chk.expect(not rd.timed_out, "objects-blocked: dump does not hang")
        combined = rd.combined
        chk.expect("panic:" not in combined.lower(), "objects-blocked: no Go panic trace",
                   clip(combined, 800))
        chk.expect(combined.strip() != "", "objects-blocked: error message on stdout/stderr")
        report = None
        if Path(j).is_file():
            report = load_report(j, chk, "objects-blocked dump report")
        if report is not None:
            if validate_report(report, chk, "objects-blocked dump report"):
                tgt = find_target(report, url, chk, "objects-blocked dump report")
                if tgt is not None:
                    res.note("objects-blocked dump report: vulnerable="
                             + repr(tgt.get("vulnerable"))
                             + " error=" + repr(clip(tgt.get("error") or "", 300)))
                    chk.expect(bool(tgt.get("error")) or tgt.get("vulnerable") is False,
                               "objects-blocked: report records the failure "
                               "(error or not vulnerable)")
        else:
            res.note("no JSON report written for failed dump (informational)")


@scenario("G-multi-target-list-and-flags")
def scenario_g_multi(ctx, res):
    chk = res.checks
    login = b"<!doctype html><html><body>login</body></html>"
    with loose_server(ctx) as srv_a,             servers.FixtureServer(ctx.loose["root"], prefix="/app", mode="soft404",
                                  name="trap") as srv_d,             servers.FixtureServer(ctx.loose["root"], prefix="/app", name="fake-head",
                                  overrides={
                                      ".git/HEAD": (200, "text/html", login),
                                      ".git/config": (200, "text/html", login),
                                  }) as srv_e:
        url_a = srv_a.url()
        url_d = srv_d.url()
        url_e = srv_e.url()
        dead = servers.dead_port()
        targets = [url_a, url_d, url_e, "http://127.0.0.1:" + str(dead) + "/none"]

        out = ctx.outdir("g-multi")
        j = ctx.file_path("json", "g-multi.json")
        r = run_tool(["scan", *targets, "-c", "8", "--per-host", "2", "--rate", "0",
                      "-t", "3s", "--retries", "1", "-o", str(out), "--json", str(j)],
                     timeout=120)
        res.record(r)
        expect_exit(chk, r, 0, "multi-target scan (1 vulnerable of 4)")
        chk.expect(not r.timed_out, "multi-target scan: no hang / timeout")
        report = load_report(j, chk, "multi scan report")
        if validate_report(report, chk, "multi scan report"):
            entries = report.get("targets", [])
            chk.expect_equal(len(entries), 4, "multi scan: one report entry per target")
            vulnerable = [t for t in entries
                          if isinstance(t, dict) and t.get("vulnerable") is True]
            chk.expect_equal(len(vulnerable), 1, "multi scan: exactly one vulnerable target")
            tg_a = find_target(report, "127.0.0.1:" + str(srv_a.port), chk,
                               "multi scan report")
            if tg_a is not None:
                expect_vulnerable(chk, tg_a, True, "multi scan: loose repo")
            tg_d = find_target(report, "127.0.0.1:" + str(srv_d.port), chk,
                               "multi scan report")
            if tg_d is not None:
                expect_vulnerable(chk, tg_d, False, "multi scan: soft-404 trap")
            tg_e = find_target(report, "127.0.0.1:" + str(srv_e.port), chk,
                               "multi scan report")
            if tg_e is not None:
                expect_vulnerable(chk, tg_e, False, "multi scan: fake-head trap")
            tg_dead = find_target(report, "127.0.0.1:" + str(dead), chk,
                                  "multi scan report")
            if tg_dead is not None:
                expect_vulnerable(chk, tg_dead, False, "multi scan: dead port not vulnerable")
                chk.expect(bool(tg_dead.get("error")),
                           "multi scan: dead port recorded an error",
                           repr(tg_dead.get("error")))

        # --list file (comments + blank lines + one target per line)
        list_path = ctx.file_path("lists", "targets.txt")
        list_lines = [
            "# gitleak e2e target list",
            "",
            targets[0],
            "# a comment between targets",
            targets[1],
            "   ",
            targets[2],
            targets[3],
            "",
        ]
        list_path.write_text(chr(10).join(list_lines), encoding="utf-8")
        out_l = ctx.outdir("g-list")
        j_l = ctx.file_path("json", "g-list.json")
        rl = run_tool(["scan", "--list", str(list_path), "-o", str(out_l),
                       "--json", str(j_l), "-t", "3s", "--retries", "1"], timeout=120)
        res.record(rl)
        expect_exit(chk, rl, 0, "scan --list file with comments")
        report_l = load_report(j_l, chk, "list scan report")
        if validate_report(report_l, chk, "list scan report"):
            entries_l = report_l.get("targets", [])
            chk.expect_equal(len(entries_l), 4, "scan --list: all 4 targets parsed")
            vuln_l = [t for t in entries_l
                      if isinstance(t, dict) and t.get("vulnerable") is True]
            chk.expect_equal(len(vuln_l), 1, "scan --list: exactly one vulnerable target")

        # flags smoke: every documented flag that is meaningful against local HTTP
        out_f = ctx.outdir("g-flags")
        j_f = ctx.file_path("json", "g-flags.json")
        rf = run_tool([
            "scan", url_a, "-o", str(out_f), "--json", str(j_f),
            "--threads", "4", "--max-body", "64", "-c", "4", "--per-host", "2",
            "--rate", "1000", "-t", "5s", "--retries", "2", "-A", "gitleak-e2e/1.0",
            "-H", "X-E2E: yes", "-H", "X-E2E-2: two", "-k", "--no-color", "--debug",
        ], timeout=120)
        res.record(rf)
        expect_exit(chk, rf, 0, "scan flags smoke")
        if validate_report(load_report(j_f, chk, "flags smoke report"), chk,
                           "flags smoke report"):
            res.note("flags smoke output chars=" + str(len(rf.combined)))

        # --quiet still succeeds
        out_q = ctx.outdir("g-quiet")
        j_q = ctx.file_path("json", "g-quiet.json")
        rq = run_tool(["scan", url_a, "-o", str(out_q), "--json", str(j_q), "--quiet"],
                      timeout=120)
        res.record(rq)
        expect_exit(chk, rq, 0, "scan --quiet")
        res.note("--quiet stdout chars=" + str(len(rq.stdout)) + " (informational)")


@scenario("H-auto-scan-then-dump")
def scenario_h_auto(ctx, res):
    chk = res.checks
    with loose_server(ctx) as srv_a,             servers.FixtureServer(ctx.loose["root"], prefix="/app", mode="soft404",
                                  name="trap") as srv_d:
        url_a = srv_a.url()
        url_d = srv_d.url()
        out = ctx.outdir("h-auto")
        j = ctx.file_path("json", "h-auto.json")
        r = run_tool(["auto", url_a, url_d, "-o", str(out), "--json", str(j),
                      "-t", "5s"], timeout=240)
        res.record(r)
        expect_exit(chk, r, 0, "auto: one vulnerable target -> exit 0")
        report = load_report(j, chk, "auto report")
        if validate_report(report, chk, "auto report"):
            entries = report.get("targets", [])
            chk.expect_equal(len(entries), 2, "auto: two report entries")
            tg_a = find_target(report, url_a, chk, "auto report")
            if tg_a is not None:
                expect_vulnerable(chk, tg_a, True, "auto: vulnerable target")
                restored = resolve_out_dir(tg_a)
                if restored is not None:
                    compare_trees(ctx.loose["files"], restored, chk, "auto restore")
            tg_d = find_target(report, "127.0.0.1:" + str(srv_d.port), chk, "auto report")
            if tg_d is not None:
                expect_vulnerable(chk, tg_d, False, "auto: soft-404 trap")
                trap_out = resolve_out_dir(tg_d)
                if trap_out is not None and trap_out.is_dir():
                    chk.expect_equal(len(fixtures.snapshot_tree(trap_out)), 0,
                                     "auto: no files restored for benign target")

        # all-benign auto -> exit 2
        out2 = ctx.outdir("h-auto-benign")
        j2 = ctx.file_path("json", "h-auto-benign.json")
        r2 = run_tool(["auto", url_d, "-o", str(out2), "--json", str(j2), "-t", "5s"],
                      timeout=120)
        res.record(r2)
        expect_exit(chk, r2, 2, "auto: no vulnerable target -> exit 2")


@scenario("I-benign-static-site")
def scenario_i_benign(ctx, res):
    chk = res.checks
    site = TMP_ROOT / "site"
    fixtures._rmtree(site)
    (site / "assets").mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_bytes(b"<!doctype html><title>plain site</title>hello")
    (site / "assets" / "app.js").write_bytes(b"console.log('hello')" + bytes([10]))
    with servers.FixtureServer(site, prefix="/site", name="benign") as srv:
        url = srv.url()
        outs = ctx.outdir("i-scan")
        js = ctx.file_path("json", "i-scan.json")
        rs = run_tool(["scan", url, "-o", str(outs), "--json", str(js)], timeout=120)
        res.record(rs)
        expect_exit(chk, rs, 2, "benign static site: scan finds nothing")
        reports = load_report(js, chk, "benign scan report")
        if reports is not None and validate_report(reports, chk, "benign scan report"):
            tg = find_target(reports, "127.0.0.1", chk, "benign scan report")
            if tg is not None:
                expect_vulnerable(chk, tg, False, "benign site scan")

        outd = ctx.outdir("i-dump")
        jd = ctx.file_path("json", "i-dump.json")
        rd = run_tool(["dump", url, "-o", str(outd), "--json", str(jd)], timeout=120)
        res.record(rd)
        expect_exit(chk, rd, 2, "benign static site: dump exits 2")


# ===========================================================================
# build + fixtures + main
# ===========================================================================

def build_binary():
    gocache = WORKSPACE / ".gocache"
    gotmp = WORKSPACE / ".gotmp"
    gocache.mkdir(parents=True, exist_ok=True)
    gotmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOCACHE"] = str(gocache)
    env["GOTMPDIR"] = str(gotmp)
    cmd = ["go", "build", "-o", str(EXE), "."]
    started = time.monotonic()
    try:
        cp = subprocess.run(cmd, cwd=str(WORKSPACE), env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=300)
    except FileNotFoundError:
        return {"ok": False, "command": format_cmd(cmd), "exit_code": None,
                "stdout": "", "stderr": "go executable not found on PATH",
                "duration": time.monotonic() - started}
    except subprocess.TimeoutExpired:
        return {"ok": False, "command": format_cmd(cmd), "exit_code": None,
                "stdout": "", "stderr": "go build timed out after 300s",
                "duration": time.monotonic() - started}
    ok = cp.returncode == 0 and EXE.is_file()
    return {"ok": ok, "command": format_cmd(cmd), "exit_code": cp.returncode,
            "stdout": cp.stdout, "stderr": cp.stderr,
            "duration": time.monotonic() - started}


def prepare(tmp_root):
    fixtures._rmtree(tmp_root)
    (tmp_root / "out").mkdir(parents=True, exist_ok=True)
    (tmp_root / "json").mkdir(parents=True, exist_ok=True)
    (tmp_root / "lists").mkdir(parents=True, exist_ok=True)
    build = build_binary()
    fixture_data = None
    fixture_error = None
    if build["ok"]:
        try:
            fixture_data = fixtures.build_all(tmp_root / "fixtures")
        except Exception:
            fixture_error = traceback.format_exc()
    return build, fixture_data, fixture_error


def run_scenarios(ctx, only):
    results = []
    matches = [m.strip() for m in (only or "").split(",") if m.strip()]
    for name, fn in SCENARIOS:
        if matches and not any(m.lower() in name.lower() for m in matches):
            continue
        res = ScenarioResult(name)
        started = time.monotonic()
        print("[ RUN  ] " + name, flush=True)
        try:
            fn(ctx, res)
        except Exception:
            res.failures.append("unexpected harness exception: "
                                + traceback.format_exc().strip().splitlines()[-1])
            res.evidence_line("TRACEBACK:" + chr(10) + clip(traceback.format_exc(), 4000))
        res.duration = time.monotonic() - started
        if res.checks.expectations == 0 and not res.failures:
            res.failures.append("scenario executed no checks")
        res.status = "FAIL" if res.failures else "PASS"
        print("[ " + res.status + " ] " + name
              + "  (" + str(res.checks.expectations) + " checks, %.2fs)" % res.duration,
              flush=True)
        for label in res.failures:
            print("         FAIL: " + label, flush=True)
        results.append(res)
    return results


def write_report(build, fixture_data, fixture_error, results, elapsed):
    lines = []
    add = lines.append
    add("# gitleak end-to-end report")
    add("")
    add("- generated_at: " + fmt_ts())
    add("- workspace: " + str(WORKSPACE))
    add("- harness: python " + sys.version.split()[0] + " (stdlib only)")
    add("- git: " + tool_version(["git", "--version"]))
    add("- go: " + tool_version(["go", "version"]))
    add("- platform: " + sys.platform + " / " + os.name)
    add("")
    add("## Binary build")
    add("")
    add("- command: " + build.get("command", "?"))
    add("- result: " + ("OK" if build.get("ok") else "FAILED"))
    add("- duration: %.2fs" % build.get("duration", 0.0))
    add("- exit_code: " + str(build.get("exit_code")))
    add("- path: " + str(EXE) + ("  (" + str(EXE.stat().st_size) + " bytes)"
                                 if EXE.is_file() else "  (missing)"))
    if build.get("stdout", "").strip():
        add("- build stdout: " + clip(build["stdout"], 2000))
    if build.get("stderr", "").strip():
        add("- build stderr: " + clip(build["stderr"], 3000))
    add("")

    add("## Fixtures")
    add("")
    if fixture_data:
        for key in ("loose", "packed"):
            info = fixture_data[key]
            add("### " + key)
            add("")
            add("- root: " + info["root"])
            add("- head_ref: " + info["head_ref"] + "  head_commit: " + info["head_commit"])
            add("- commits (HEAD): " + str(info["commits"]) + "  branches: "
                + ", ".join(info["branches"]))
            add("- worktree files: " + str(info["file_count"])
                + "  bytes: " + str(info["total_bytes"]))
            add("- remote.origin.url: " + info["remote_url"])
            add("- packed: " + str(info["packed"]) + "  pack_files: "
                + repr(info["pack_files"]) + "  loose_object_files: "
                + str(info.get("loose_object_files", "-")))
            add("")
    else:
        if not build.get("ok"):
            add("- skipped: binary build failed (fixtures are built only after a")
            add("  successful build)")
        else:
            add("- FIXTURE BUILD FAILED")
        add("")
        if fixture_error:
            add(FENCE)
            add(clip(fixture_error, 4000))
            add(FENCE)
            add("")

    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    add("## Summary")
    add("")
    add("| # | scenario | status | checks | duration |")
    add("|---|----------|--------|--------|----------|")
    for index, res in enumerate(results, 1):
        add("| " + str(index) + " | " + res.name + " | **" + res.status + "** | "
            + str(res.checks.expectations) + " | %.2fs |" % res.duration)
    add("")
    add("- total: " + str(len(results)) + "  PASS: " + str(passed)
        + "  FAIL: " + str(failed))
    add("- wall clock: %.1fs" % elapsed)
    add("")

    defects = [res for res in results if res.status == "FAIL"]
    add("## Defects / failing checks")
    add("")
    if not results:
        add("No scenarios ran (build/fixture failure -- see the sections above).")
        add("")
    elif not defects:
        add("None. All scenarios passed.")
        add("")
    else:
        for res in defects:
            add("### " + res.name)
            add("")
            for label in res.failures:
                add("- " + label)
            add("")
            if res.evidence:
                add("Commands / evidence:")
                add("")
                add(FENCE)
                for entry in res.evidence:
                    add(clip(entry, 3000))
                add(FENCE)
                add("")

    add("## Scenario details")
    add("")
    for index, res in enumerate(results, 1):
        add("### " + str(index) + ". " + res.name + " -- " + res.status
            + " (" + str(res.checks.expectations) + " checks, %.2fs)" % res.duration)
        add("")
        if res.notes:
            add("Notes:")
            add("")
            for note in res.notes:
                add("- " + clip(note, 1200))
            add("")
        if res.evidence:
            add("Commands executed (exit code / duration):")
            add("")
            add(FENCE)
            for entry in res.evidence:
                add(clip(entry, 2500))
            add(FENCE)
            add("")
        if res.failures:
            add("Failures:")
            add("")
            for label in res.failures:
                add("- " + label)
            add("")
    add("## Coverage notes")
    add("")
    add("- Scenarios: loose-objects scan/dump, target-form normalization, deterministic slug,")
    add("  byte-exact tree comparison, --resume, --write-git usability, packfile dump,")
    add("  --history --all-branches --write-git, missing .git/index fallback,")
    add("  soft-404 / fake-HEAD traps, blocked objects, multi-target + --list, flags smoke,")
    add("  auto scan-then-dump, benign static site, version/usage exit codes.")
    add("- Not covered: --proxy (no proxy server in this harness), TLS/https targets,")
    add("  default ./gitleak-out root (tests always pass -o), interactive/TTY behavior.")
    add("")
    REPORT_PATH.write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
    return REPORT_PATH


def main(argv=None):
    import argparse

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="gitleak end-to-end harness")
    parser.add_argument("--only", default="",
                        help="comma separated scenario name substrings")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse existing gitleak.exe")
    parser.add_argument("--keep-tmp", action="store_true",
                        help="keep tests/_tmp for debugging")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = parser.parse_args(argv)

    if args.list:
        for name, _fn in SCENARIOS:
            print(name)
        return 0

    started = time.monotonic()
    TMP_ROOT.mkdir(parents=True, exist_ok=True)

    if args.no_build:
        build = {"ok": EXE.is_file(), "command": "(build skipped via --no-build)",
                 "exit_code": None, "stdout": "",
                 "stderr": "" if EXE.is_file() else "gitleak.exe missing",
                 "duration": 0.0}
        fixture_error = None
        fixture_data = None
        if build["ok"]:
            try:
                fixture_data = fixtures.build_all(TMP_ROOT / "fixtures")
            except Exception:
                fixture_error = traceback.format_exc()
    else:
        build, fixture_data, fixture_error = prepare(TMP_ROOT)

    results = []
    if build["ok"] and fixture_data is not None:
        ctx = Ctx(fixture_data)
        results = run_scenarios(ctx, args.only)
    elif not build["ok"]:
        print("[BUILD] FAILED: "
              + clip((build.get("stderr") or build.get("stdout") or "").strip(), 2000),
              flush=True)
    elif fixture_error:
        print("[FIXTURES] FAILED:" + chr(10) + clip(fixture_error, 2000), flush=True)

    elapsed = time.monotonic() - started
    report_path = write_report(build, fixture_data, fixture_error, results, elapsed)

    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    print("")
    print("=" * 72)
    print("SUMMARY: %d scenarios, %d PASS, %d FAIL, %.1fs"
          % (len(results), passed, failed, elapsed))
    print("report: " + str(report_path))
    for res in results:
        print("  " + res.status + "  " + res.name)
    print("=" * 72)

    if not args.keep_tmp:
        try:
            fixtures._rmtree(TMP_ROOT)
            print("cleaned: " + str(TMP_ROOT))
        except Exception as exc:
            print("WARN: temp cleanup failed: " + str(exc))

    if not build["ok"] or fixture_data is None:
        return 2
    if not results:
        return 2
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
