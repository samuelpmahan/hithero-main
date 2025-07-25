from fastapi import APIRouter

from app.apis.v1.endpoints import auth, users, teachers, admin, utils

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(teachers.router, prefix="/teachers", tags=["teachers"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(utils.router, prefix="/utils", tags=["utils"])