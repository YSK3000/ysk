"""Test bootstrap: import from ../src and never touch the real data directory."""
import logging
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KEKKAI_HOME"] = tempfile.mkdtemp(prefix="kekkai-test-")
os.environ.setdefault("NO_COLOR", "1")


def fixture(*parts: str) -> str:
    with open(os.path.join(HERE, "fixtures", *parts), "r", encoding="utf-8") as f:
        return f.read()

logging.getLogger("kekkai").setLevel(logging.CRITICAL)
