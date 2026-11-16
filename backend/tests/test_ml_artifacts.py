from pathlib import Path

import pytest

from app.services.ml.artifacts import load_model_artifact, save_model_artifact


def test_model_artifact_round_trip_uses_private_generated_file(tmp_path: Path) -> None:
    storage = tmp_path / "models"
    key = save_model_artifact({"model": "application-generated"}, storage)

    assert len(key) == 39
    assert load_model_artifact(storage, key) == {"model": "application-generated"}
    assert (storage / key).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "key", ["../outside.joblib", "/tmp/model.joblib", "user.pkl", "a" * 32 + ".joblib/../x"]
)
def test_artifact_loader_rejects_untrusted_keys(tmp_path: Path, key: str) -> None:
    with pytest.raises(ValueError, match="artifact key"):
        load_model_artifact(tmp_path, key)
