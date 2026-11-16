import os
import re
import tempfile
from pathlib import Path
from uuid import uuid4

import joblib

ARTIFACT_KEY_PATTERN = re.compile(r"^[a-f0-9]{32}\.joblib$")


def save_model_artifact(model: object, storage_dir: Path) -> str:
    storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _set_mode(storage_dir, 0o700)
    key = f"{uuid4().hex}.joblib"
    destination = _artifact_path(storage_dir, key)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".model-", suffix=".tmp", dir=storage_dir)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        joblib.dump(model, temporary)
        _set_mode(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return key


def load_model_artifact(storage_dir: Path, key: str) -> object:
    path = _artifact_path(storage_dir, key)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("The model artifact is unavailable.")
    return joblib.load(path)


def remove_model_artifact(storage_dir: Path, key: str) -> None:
    try:
        _artifact_path(storage_dir, key).unlink(missing_ok=True)
    except ValueError:
        return


def _artifact_path(storage_dir: Path, key: str) -> Path:
    if not ARTIFACT_KEY_PATTERN.fullmatch(key):
        raise ValueError("Invalid application model artifact key.")
    root = storage_dir.resolve()
    path = (root / key).resolve()
    if path.parent != root:
        raise ValueError("Model artifact path is outside managed storage.")
    return path


def _set_mode(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        # Some supported filesystems do not expose POSIX permission bits.
        pass
