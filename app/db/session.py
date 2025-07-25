from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

SQLALCHEMY_DATABASE_URL = f"mssql+pyodbc://{settings.DATABASE_UID}:{settings.DATABASE_PASSWORD}@{settings.DATABASE_SERVER}:{settings.DATABASE_PORT}/{settings.DATABASE_NAME}?driver=ODBC+Driver+18+for+SQL+Server"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)