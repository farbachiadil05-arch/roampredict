"""Which copy of RoamPredict is running: its git commit and folder.

Walk logs get pasted into chats; a line saying exactly which code produced
them saves guessing (two clones of the project on one laptop are easy to mix
up).  The commit is read straight from the files in ``.git``, so no git
program is needed.  Only ``HEAD``, refs and ``packed-refs`` are read - never
``.git/config``, which can hold remote URLs with tokens.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["code_identity", "git_commit"]

_HEX = frozenset("0123456789abcdef")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _git_dir(root: Path) -> Path | None:
    dot = root / ".git"
    if dot.is_dir():
        return dot
    if dot.is_file():  # a worktree or submodule: ".git" holds "gitdir: <path>"
        text = _read(dot)
        if text.startswith("gitdir:"):
            path = Path(text[len("gitdir:") :].strip())
            return path if path.is_absolute() else (root / path).resolve()
    return None


def _resolve_ref(git_dir: Path, ref: str) -> str | None:
    dirs = [git_dir]
    common = git_dir / "commondir"  # worktrees keep shared refs here
    if common.is_file():
        dirs.append((git_dir / _read(common)).resolve())
    for d in dirs:
        loose = d / ref
        if loose.is_file():
            return _read(loose)
        packed = d / "packed-refs"
        if packed.is_file():
            for line in _read(packed).splitlines():
                sha, _, name = line.partition(" ")
                if name == ref and not line.startswith(("#", "^")):
                    return sha
    return None


def git_commit(root: Path) -> str | None:
    """Short commit hash of the git checkout at ``root``, or None."""
    try:
        git_dir = _git_dir(root)
        if git_dir is None:
            return None
        head = _read(git_dir / "HEAD")
        sha = _resolve_ref(git_dir, head[len("ref:") :].strip()) if head.startswith("ref:") else head
    except OSError:
        return None
    if sha and len(sha) >= 7 and set(sha.lower()) <= _HEX:
        return sha[:7].lower()
    return None


def code_identity() -> str:
    """For example ``code 4b8e73c in C:\\...\\python-debana``."""
    root = Path(__file__).resolve().parent.parent
    commit = git_commit(root)
    return f"code {commit or 'of unknown version (not a git checkout)'} in {root}"
