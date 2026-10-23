from fastapi import APIRouter

router = APIRouter()


@router.get("/health", summary="Service health check")
async def health_check() -> dict:
    """Returns the operational status of the analysis microservice."""
    return {"status": "ok"}
