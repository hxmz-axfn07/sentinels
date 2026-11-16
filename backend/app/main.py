from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyses import router as analyses_router
from app.api.dashboard import router as dashboard_router
from app.api.detections import router as detections_router
from app.api.flows import router as flows_router
from app.api.health import router as health_router
from app.api.hybrid import router as hybrid_router
from app.api.ml import router as ml_router
from app.api.pipeline import router as pipeline_router
from app.api.upload_limits import UploadRequestSizeLimitMiddleware
from app.core.config import settings

app = FastAPI(title="SENTINEL API", version="0.1.0")
app.add_middleware(UploadRequestSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(health_router)
app.include_router(dashboard_router)
app.include_router(analyses_router)
app.include_router(flows_router)
app.include_router(detections_router)
app.include_router(hybrid_router)
app.include_router(pipeline_router)
app.include_router(ml_router)
