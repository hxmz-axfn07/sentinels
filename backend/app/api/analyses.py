import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.analysis import Analysis
from app.models.packet import PacketRecord
from app.schemas.analysis import AnalysisList, AnalysisRead, PacketList, UploadLimits
from app.services.analysis import mark_analysis_failed, process_capture
from app.services.capture_format import CaptureValidationError, inspect_capture
from app.services.upload import UploadTooLargeError, stage_upload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyses", tags=["analyses"])


@router.get("/limits", response_model=UploadLimits)
def upload_limits() -> UploadLimits:
    return UploadLimits(max_upload_size_bytes=settings.max_upload_size_bytes)


@router.post("/upload", response_model=AnalysisRead, status_code=201)
def upload_capture(file: UploadFile, db: Session = Depends(get_db)) -> AnalysisRead:  # noqa: B008
    original_filename = ""
    staging_path: Path | None = None
    stored_path: Path | None = None
    analysis: Analysis | None = None
    analysis_persisted = False

    try:
        original_filename = _display_filename(file.filename)
        staging_path, file_size = stage_upload(
            file.file, settings.upload_storage_dir, settings.max_upload_size_bytes
        )
        if file_size == 0:
            raise HTTPException(
                status_code=422,
                detail={"code": "empty_file", "message": "The uploaded file is empty."},
            )
        capture_format = inspect_capture(staging_path)
        storage_key = f"{uuid.uuid4().hex}{capture_format.suffix}"
        stored_path = settings.upload_storage_dir / storage_key
        staging_path.replace(stored_path)
        staging_path = None

        analysis = Analysis(
            original_filename=original_filename,
            storage_key=storage_key,
            file_size_bytes=file_size,
            capture_format=capture_format.value,
            status="pending",
            packet_count=0,
        )
        db.add(analysis)
        db.commit()
        analysis_persisted = True
        db.refresh(analysis)

        analysis.status = "processing"
        db.commit()
        process_capture(db, analysis, stored_path)
        db.refresh(analysis)
        return AnalysisRead.model_validate(analysis)
    except UploadTooLargeError:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "upload_too_large",
                "message": f"The maximum upload size is {settings.max_upload_size_bytes} bytes.",
            },
        ) from None
    except CaptureValidationError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": error.code, "message": error.message},
        ) from None
    except HTTPException:
        raise
    except Exception as error:
        if analysis is None or not analysis_persisted:
            db.rollback()
            if stored_path is not None:
                stored_path.unlink(missing_ok=True)
            logger.error("Upload setup failed (%s)", type(error).__name__)
            raise HTTPException(
                status_code=500,
                detail={"code": "upload_failed", "message": "The capture could not be stored."},
            ) from None

        try:
            failed = mark_analysis_failed(db, analysis.id, "Packet processing did not complete.")
        except Exception as database_error:
            logger.error(
                "Could not persist failed analysis %s (%s)",
                analysis.id,
                type(database_error).__name__,
            )
            raise HTTPException(
                status_code=500,
                detail={"code": "analysis_failed", "message": "Analysis processing failed."},
            ) from None
        logger.error("Analysis %s failed (%s)", analysis.id, type(error).__name__)
        return AnalysisRead.model_validate(failed)
    finally:
        if staging_path is not None:
            staging_path.unlink(missing_ok=True)
        file.file.close()


@router.get("", response_model=AnalysisList)
def list_analyses(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),  # noqa: B008
) -> AnalysisList:
    total = db.scalar(select(func.count()).select_from(Analysis)) or 0
    items = db.scalars(
        select(Analysis)
        .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return AnalysisList(items=items, total=total, offset=offset, limit=limit)


@router.get("/{analysis_id}", response_model=AnalysisRead)
def get_analysis(analysis_id: int, db: Session = Depends(get_db)) -> Analysis:  # noqa: B008
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


@router.get("/{analysis_id}/packets", response_model=PacketList)
def list_packets(
    analysis_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),  # noqa: B008
) -> PacketList:
    if db.get(Analysis, analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    query = select(PacketRecord).where(PacketRecord.analysis_id == analysis_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(PacketRecord.packet_index).offset(offset).limit(limit)).all()
    return PacketList(items=items, total=total, offset=offset, limit=limit)


def _display_filename(filename: str | None) -> str:
    if not filename:
        raise HTTPException(
            status_code=422,
            detail={"code": "missing_filename", "message": "A filename is required."},
        )
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(
        character for character in basename if character >= " " and character != "\x7f"
    )
    cleaned = cleaned.strip(" .")[:255]
    if not cleaned:
        return "capture"
    return cleaned
