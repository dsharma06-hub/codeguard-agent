from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routes.health import router as health_router
from app.routes.analyze import router as analyze_router, analyze_rescan_endpoint, AnalyzeRequest, AnalyzeResponse


def create_app() -> FastAPI:
    """Application factory for CodeGuard Analysis Microservice."""
    app = FastAPI(
        title="CodeGuard Analysis Service",
        description="Static code analysis microservice for parsing ASTs, detecting vulnerabilities, and generating attack-path graphs.",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Configure CORS middleware
    origins = (
        settings.CORS_ORIGINS
        if isinstance(settings.CORS_ORIGINS, list)
        else [settings.CORS_ORIGINS]
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routers
    app.include_router(health_router, tags=["Health"])
    app.include_router(analyze_router)

    # Direct /rescan endpoint for rescan requests
    @app.post("/rescan", response_model=AnalyzeResponse, tags=["Analysis"])
    def rescan_file(request: AnalyzeRequest) -> AnalyzeResponse:
        return analyze_rescan_endpoint(request)

    return app



app = create_app()
