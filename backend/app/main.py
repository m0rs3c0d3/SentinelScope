from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings
from app.routers import threat_intel, net_scanner, log_analyzer

settings = get_settings()

app = FastAPI(
    title="SentinelScope",
    description="Cybersecurity threat intelligence aggregation toolkit",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(threat_intel.router)
app.include_router(net_scanner.router)
app.include_router(log_analyzer.router)


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "operational",
        "version": "1.0.0",
        "services": settings.available_services,
    }
