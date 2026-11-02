"""Fixture repository builder for the gitleak end-to-end harness (stdlib only).

Everything is created under the repository's tests/_tmp directory so all writes
stay inside the session workspace (the sandbox blocks writes outside it).

Fixture layout (built by build_all):
  loose/  2+ commits, 2 branches, tags, unicode / space / hash / percent names,
          an empty file, a binary file with NUL bytes, a ~200KB file and
          130+ small files (exercises concurrency).
  packed/ exact copy of loose after git gc --aggressive --prune=now so the
          loose objects are gone and only .git/objects/pack/*.pack remains.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Isolated HOME/GIT env so the machine's global git config cannot influence
# fixture bytes (autocrlf, filters, signing, ...).
_COMMIT_ENV = {
    "GIT_AUTHOR_NAME": "gitleak e2e",
    "GIT_AUTHOR_EMAIL": "e2e@example.com",
    "GIT_COMMITTER_NAME": "gitleak e2e",
    "GIT_COMMITTER_EMAIL": "e2e@example.com",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "echo",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
}

_GIT_BASE = [
    "-c", "core.autocrlf=false",
    "-c", "core.symlinks=false",
    "-c", "core.filemode=false",
    "-c", "core.precomposeunicode=false",
    "-c", "commit.gpgsign=false",
    "-c", "tag.gpgsign=false",
    "-c", "advice.detachedHead=false",
    "-c", "user.name=gitleak e2e",
    "-c", "user.email=e2e@example.com",
]

REMOTE_URL = "https://example.com/secret/repo.git"

# ---------------------------------------------------------------------------
# file payloads
# ---------------------------------------------------------------------------

README_1 = b"""# Secret Repo

line 1
line 2
"""

README_2 = b"""# Secret Repo

line 1 (updated in commit 2)
line 2
"""

SMALL_FILES = {
    "README.md": README_1,
    "nested/dir/file.txt": b"""nested content
""",
    "empty.txt": b"",
    "name with spaces.txt": b"""file whose name contains spaces
""",
    "hash#and%percent%.txt": b"""special characters: hash # and percent %
""",
}

SECOND_COMMIT_FILES = {
    "中文文件名.txt": """中文内容 line one
line two
""".encode("utf-8"),
    "assets/binary.bin": bytes(range(256)) * 4,          # 1 KiB, contains NULs
    "assets/large_200k.bin": bytes(range(256)) * 782,    # 200,192 bytes
    "deep/a/b/c/d/e/file.txt": b"""deeply nested file
""",
    "README.md": README_2,
}

MANY_FILE_COUNT = 130


def _many_files():
    return {
        "many/file%03d.txt" % i: ("concurrency probe %03d" % i).encode("ascii") + bytes([10])
        for i in range(MANY_FILE_COUNT)
    }


THIRD_COMMIT_FILES = {
    "nested/dir/second.txt": b"""added in commit 3
""",
    "README.md": b"""# Secret Repo

line 1 (updated in commit 3)
line 2
""",
}

FEATURE_BRANCH_FILES = {
    "feature/only-on-branch.txt": b"""this file only exists on the feature branch
""",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _rmtree(path):
    """shutil.rmtree that copes with read-only git files on Windows."""
    def _onerror(func, p, excinfo):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass

    if Path(path).exists():
        shutil.rmtree(str(path), onerror=_onerror)


def _write(root, rel, data):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def git(args, cwd, env=None, check=True):
    """Run one git command with isolated config; returns CompletedProcess."""
    run_env = os.environ.copy()
    run_env.update(_COMMIT_ENV)
    if env:
        run_env.update(env)
    cmd = ["git", *_GIT_BASE, *args]
    cp = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=run_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and cp.returncode != 0:
        raise RuntimeError(
            "git failed (%d): %s cwd=%s stdout=%r stderr=%r"
            % (cp.returncode, " ".join(cmd), cwd, cp.stdout, cp.stderr)
        )
    return cp


def git_out(args, cwd, env=None):
    return git(args, cwd, env=env).stdout.strip()


# ---------------------------------------------------------------------------
# tree snapshots
# ---------------------------------------------------------------------------

def snapshot_tree(root):
    """Map posix-relative path -> {'sha256','size'} for every regular file.

    .git directories are always pruned. Symlink handling follows the platform:
    git on Windows stores symlinks as plain files, which is what we compare.
    """
    root = Path(root)
    out = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            try:
                data = p.read_bytes()
            except OSError as exc:  # pragma: no cover - unreadable file
                out[rel] = {"sha256": "unreadable:" + str(exc), "size": -1}
                continue
            out[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return out


def tree_summary(tree):
    return len(tree), sum(v["size"] for v in tree.values())


# ---------------------------------------------------------------------------
# fixture construction
# ---------------------------------------------------------------------------

def build_loose_repo(root, home_dir=None):
    """Build the 'loose objects' fixture repo; returns metadata dict."""
    root = Path(root)
    env = {"HOME": str(home_dir)} if home_dir else None
    _rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    git(["init", "-b", "main"], cwd=root, env=env)

    # commit 1: small/plain/odd file names
    for rel, data in SMALL_FILES.items():
        _write(root, rel, data)
    git(["add", "-A"], cwd=root, env=env)
    git(["commit", "-m", "c1: base files"], cwd=root, env=env)
    git(["tag", "v1.0"], cwd=root, env=env)

    # commit 2: unicode, binary, large, deep, many small files
    for rel, data in SECOND_COMMIT_FILES.items():
        _write(root, rel, data)
    for rel, data in _many_files().items():
        _write(root, rel, data)
    git(["add", "-A"], cwd=root, env=env)
    git(["commit", "-m", "c2: unicode binary large many"], cwd=root, env=env)

    # divergent feature branch (objects exist for it, not part of HEAD tree)
    git(["branch", "feature"], cwd=root, env=env)
    git(["checkout", "-b", "feature-wip"], cwd=root, env=env)
    for rel, data in FEATURE_BRANCH_FILES.items():
        _write(root, rel, data)
    git(["add", "-A"], cwd=root, env=env)
    git(["commit", "-m", "feature: branch-only file"], cwd=root, env=env)
    git(["checkout", "main"], cwd=root, env=env)

    # commit 3 on main
    for rel, data in THIRD_COMMIT_FILES.items():
        _write(root, rel, data)
    git(["add", "-A"], cwd=root, env=env)
    git(["commit", "-m", "c3: update readme add nested"], cwd=root, env=env)

    git(["remote", "add", "origin", REMOTE_URL], cwd=root, env=env)
    git(["config", "core.autocrlf", "false"], cwd=root, env=env)

    return _describe(root, "loose", packed=False)


def build_packed_repo(root, home_dir=None, source_root=None):
    """Copy a loose fixture then git gc --aggressive --prune=now it."""
    root = Path(root)
    env = {"HOME": str(home_dir)} if home_dir else None
    _rmtree(root)
    if source_root is not None:
        root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(str(source_root), str(root))
    else:  # pragma: no cover - standalone use
        build_loose_repo(root, home_dir)

    git(["reflog", "expire", "--expire=now", "--all"], cwd=root, env=env)
    git(["gc", "--aggressive", "--prune=now"], cwd=root, env=env)

    info = _describe(root, "packed", packed=True)
    packdir = root / ".git" / "objects" / "pack"
    packs = sorted(packdir.glob("*.pack")) if packdir.is_dir() else []
    info["pack_files"] = [p.name for p in packs]
    info["loose_object_files"] = _count_loose_objects(root)
    if not packs:
        raise RuntimeError("git gc did not produce a .pack file in " + str(packdir))
    return info


def _count_loose_objects(root):
    objdir = Path(root) / ".git" / "objects"
    n = 0
    if objdir.is_dir():
        for entry in objdir.iterdir():
            name = entry.name.lower()
            if entry.is_dir() and len(name) == 2 and all(c in "0123456789abcdef" for c in name):
                n += sum(1 for _ in entry.iterdir())
    return n


def _describe(root, fixture_id, packed):
    root = Path(root)
    tree = snapshot_tree(root)
    count, total = tree_summary(tree)
    head_commit = git_out(["rev-parse", "HEAD"], root)
    head_ref = git_out(["symbolic-ref", "HEAD"], root)
    remote_url = ""
    cp = git(["config", "--get", "remote.origin.url"], cwd=root, check=False)
    if cp.returncode == 0:
        remote_url = cp.stdout.strip()
    branches = [b.strip() for b in git_out(["for-each-ref", "--format=%(refname:short)", "refs/heads"], root).splitlines() if b.strip()]
    commits = int(git_out(["rev-list", "--count", "HEAD"], root) or "0")
    status = git_out(["status", "--porcelain"], root)
    if status:
        raise RuntimeError("fixture worktree is dirty after build: " + status)
    return {
        "id": fixture_id,
        "root": str(root),
        "head_ref": head_ref,
        "head_commit": head_commit,
        "remote_url": remote_url,
        "branches": branches,
        "commits": commits,
        "packed": packed,
        "files": tree,
        "file_count": count,
        "total_bytes": total,
        "pack_files": [],
    }


def build_all(tmp_root):
    """Build both fixtures under tmp_root; returns dict with home/loose/packed."""
    tmp_root = Path(tmp_root)
    tmp_root.mkdir(parents=True, exist_ok=True)
    home = tmp_root / "home"
    home.mkdir(parents=True, exist_ok=True)
    repos = tmp_root / "repos"
    loose = build_loose_repo(repos / "loose", home)
    packed = build_packed_repo(repos / "packed", home, source_root=Path(loose["root"]))
    return {"home": str(home), "loose": loose, "packed": packed}


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------

def _selftest():
    here = Path(__file__).resolve().parent
    base = here / "_tmp" / "selftest-fixtures"
    _rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    try:
        data = build_all(base)
        for key in ("loose", "packed"):
            info = data[key]
            print("[%s] root=%s" % (key, info["root"]))
            print("  head_ref=%s head_commit=%s commits=%d branches=%s"
                  % (info["head_ref"], info["head_commit"][:12], info["commits"], ",".join(info["branches"])))
            print("  files=%d bytes=%d remote=%s packed=%s packs=%s loose_objs=%s"
                  % (info["file_count"], info["total_bytes"], info["remote_url"],
                     info["packed"], info["pack_files"], info.get("loose_object_files", "-")))
        loose, packed = data["loose"], data["packed"]
        assert loose["head_commit"] == packed["head_commit"], "packed copy must keep commit hashes"
        assert loose["files"] == packed["files"], "packed worktree must equal loose worktree"
        assert packed["pack_files"], "packed fixture has no packfile"
        assert packed.get("loose_object_files", 0) == 0, "packed fixture still has loose objects"
        for rel in ("中文文件名.txt", "hash#and%percent%.txt", "name with spaces.txt",
                    "empty.txt", "assets/binary.bin"):
            assert rel in loose["files"], "missing fixture file " + repr(rel)
        assert loose["files"]["empty.txt"]["size"] == 0
        expected = len(set(SMALL_FILES) | set(SECOND_COMMIT_FILES) | set(_many_files()) | set(THIRD_COMMIT_FILES))
        assert loose["file_count"] == expected, "file_count %d != %d" % (loose["file_count"], expected)
        print("SELFTEST PASS: %d files, %d bytes, packed loose_objs=%d"
              % (loose["file_count"], loose["total_bytes"], packed.get("loose_object_files", -1)))
        return 0
    finally:
        _rmtree(base)


if __name__ == "__main__":
    sys.exit(_selftest())
