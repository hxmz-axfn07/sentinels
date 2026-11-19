import os
import tempfile
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 64 * 1024


class UploadTooLargeError(ValueError):
    pass


def stage_upload(source: BinaryIO, storage_dir: Path, max_bytes: int) -> tuple[Path, int]:
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_dir.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".upload-", suffix=".part", dir=storage_dir
    )
    temporary_path = Path(temporary_name)
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as destination:
            while chunk := source.read(CHUNK_SIZE):
                size += len(chunk)
                if size > max_bytes:
                    raise UploadTooLargeError
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        return temporary_path, size
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
