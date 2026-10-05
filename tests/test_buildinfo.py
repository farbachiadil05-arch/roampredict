"""Which copy of the code is running (read from .git without a git program)."""

from pathlib import Path

import roampredict
from roampredict.buildinfo import code_identity, git_commit

SHA = "4b8e73c1d2e3f405162738495a6b7c8d9e0f1a2b"
REF = "refs/heads/claude/upbeat-newton-gh5kgn"


def make_repo(root: Path, *, loose: bool = True) -> Path:
    git = root / ".git"
    (git / "refs" / "heads" / "claude").mkdir(parents=True)
    (git / "HEAD").write_text(f"ref: {REF}\n", encoding="utf-8")
    if loose:
        (git / REF).write_text(SHA + "\n", encoding="utf-8")
    else:
        (git / "packed-refs").write_text(f"# pack-refs with: peeled\n{SHA} {REF}\n^{'0' * 40}\n", encoding="utf-8")
    return git


def test_branch_ref_loose_or_packed(tmp_path):
    make_repo(tmp_path / "a")
    make_repo(tmp_path / "b", loose=False)
    assert git_commit(tmp_path / "a") == "4b8e73c"
    assert git_commit(tmp_path / "b") == "4b8e73c"


def test_detached_head_and_worktree_file(tmp_path):
    git = make_repo(tmp_path / "main")
    (git / "HEAD").write_text(SHA.upper() + "\n", encoding="utf-8")
    assert git_commit(tmp_path / "main") == "4b8e73c"
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {git}\n", encoding="utf-8")
    assert git_commit(wt) == "4b8e73c"


def test_not_a_checkout_or_garbage(tmp_path):
    assert git_commit(tmp_path) is None
    git = make_repo(tmp_path / "x")
    (git / REF).write_text("not a hash\n", encoding="utf-8")
    assert git_commit(tmp_path / "x") is None


def test_code_identity_names_the_folder():
    text = code_identity()
    assert text.startswith("code ") and str(Path(roampredict.__file__).resolve().parent.parent) in text
