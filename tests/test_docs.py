"""The public documents: what a stranger reads on GitHub and PyPI."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ("README.md", "docs/setup.md", "CONTRIBUTING.md", "SECURITY.md")


def test_readme_leads_with_experimental():
    assert (ROOT / "README.md").read_text().splitlines()[0].startswith("> **Experimental, report-only.**")


def test_licence_is_mit():
    t = (ROOT / "LICENSE").read_text()
    assert t.startswith("MIT License") and "Abubakar Jutt" in t


def test_docs_hold_no_private_paths():
    for f in PUBLIC:
        t = (ROOT / f).read_text()
        assert "research_notes" not in t and "CodeReview" not in t and "proof/" not in t


def test_docs_hold_no_process_words():
    for f in PUBLIC:
        t = (ROOT / f).read_text()
        assert "Ruling" not in t and "Task " not in t
