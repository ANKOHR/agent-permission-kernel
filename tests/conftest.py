from pathlib import Path

import pytest

from apk.compiler import load_policy


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy():
    return load_policy(ROOT / "apk" / "data" / "default_policy.yaml")

