from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/net-scanner", tags=["Network Scanner"])


@router.get("/status")
async def scanner_status():
    return {"module": "net-scanner", "status": "coming_soon", "version": "0.0.0"}
