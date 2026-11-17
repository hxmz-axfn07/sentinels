from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.incident import Incident
from app.schemas.incidents import (
    IncidentCreate,
    IncidentDetail,
    IncidentEvidenceAttach,
    IncidentList,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentStatusUpdate,
    IncidentSummary,
    IncidentUpdate,
)
from app.services.incidents import (
    IncidentReferenceError,
    IncidentTransitionError,
    add_evidence,
    add_note,
    create_incident,
    get_incident,
    incident_summary,
    list_incidents,
    remove_evidence,
    update_incident,
    update_status,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("/summary", response_model=IncidentSummary)
def get_incident_summary(db: Session = Depends(get_db)) -> IncidentSummary:  # noqa: B008
    return incident_summary(db)


@router.get("", response_model=IncidentList)
def get_incidents(
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    status_filter: Literal["open", "acknowledged", "investigating", "resolved", "closed"]
    | None = Query(None, alias="status"),
    priority: Literal["low", "medium", "high", "critical"] | None = None,
    search: str | None = Query(None, min_length=1, max_length=100),
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentList:
    return list_incidents(
        db,
        offset=offset,
        limit=limit,
        status=status_filter,
        priority=priority,
        search=search,
    )


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED)
def post_incident(
    data: IncidentCreate,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentDetail:
    try:
        incident = create_incident(db, data)
        db.commit()
        return get_incident(db, incident.id)  # type: ignore[return-value]
    except IncidentReferenceError as error:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(error)) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Incident evidence changed; retry the request."
        ) from None


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentDetail:
    result = get_incident(db, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return result


@router.patch("/{incident_id}", response_model=IncidentDetail)
def patch_incident(
    incident_id: int,
    data: IncidentUpdate,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentDetail:
    incident = _get_incident(db, incident_id)
    update_incident(db, incident, data)
    db.commit()
    return get_incident(db, incident_id)  # type: ignore[return-value]


@router.patch("/{incident_id}/status", response_model=IncidentDetail)
def patch_incident_status(
    incident_id: int,
    data: IncidentStatusUpdate,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentDetail:
    incident = _get_incident(db, incident_id)
    try:
        update_status(db, incident, data)
    except IncidentTransitionError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(error)) from None
    db.commit()
    return get_incident(db, incident_id)  # type: ignore[return-value]


@router.post("/{incident_id}/evidence", response_model=IncidentDetail)
def post_incident_evidence(
    incident_id: int,
    data: IncidentEvidenceAttach,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentDetail:
    incident = _get_incident(db, incident_id)
    try:
        added = add_evidence(db, incident, data.event_ids)
        if added:
            incident.updated_at = datetime.now(UTC)
        db.commit()
    except IncidentReferenceError as error:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(error)) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="Incident evidence changed; retry the request."
        ) from None
    return get_incident(db, incident_id)  # type: ignore[return-value]


@router.delete("/{incident_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident_evidence(
    incident_id: int,
    evidence_id: int,
    db: Session = Depends(get_db),  # noqa: B008
) -> Response:
    incident = _get_incident(db, incident_id)
    if not remove_evidence(db, incident, evidence_id):
        raise HTTPException(status_code=404, detail="Incident evidence not found.")
    incident.updated_at = datetime.now(UTC)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{incident_id}/notes", response_model=IncidentNoteRead, status_code=201)
def post_incident_note(
    incident_id: int,
    data: IncidentNoteCreate,
    db: Session = Depends(get_db),  # noqa: B008
) -> IncidentNoteRead:
    incident = _get_incident(db, incident_id)
    note = add_note(db, incident, data)
    db.commit()
    db.refresh(note)
    return IncidentNoteRead.model_validate(note)


def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident
