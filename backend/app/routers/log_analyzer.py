from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/log-analyzer", tags=["Log Analyzer"])


@router.get("/status")
async def analyzer_status():
    return {"module": "log-analyzer", "status": "coming_soon", "version": "0.0.0"}
