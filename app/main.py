from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

from app.core.config import settings
from app.db.session import engine
from app.db import base
from app.apis.v1 import api_router

def create_app() -> FastAPI:
    """
    Creates the FastAPI application.
    """
    # Create all tables in the database.
    # For production, it is recommended to use a database migration tool like Alembic.
    base.Base.metadata.create_all(bind=engine)

    app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json"
    )

    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")
    app.mount("/pages", StaticFiles(directory="pages"), name="pages")


    # Add session middleware
    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

    # Include the API router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    return app

app = create_app()