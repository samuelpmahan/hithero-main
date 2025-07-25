from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.orm import Session

from app.apis.v1 import schemas
from app.core import security
from app.db import models
from app.db.session import SessionLocal
from app.services.email_service import send_email
from app.services.recaptcha_service import verify_recaptcha

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register/", status_code=status.HTTP_201_CREATED)
def register_user(
    recaptcha_response: str = Form(...),
    user: schemas.UserCreate = Depends(),
    db: Session = Depends(get_db)
):
    """
    Handles new user registration.
    """
    if not verify_recaptcha(recaptcha_response):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed. Please try again.",
        )

    existing_user = db.query(models.RegisteredUsers).filter(models.RegisteredUsers.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists.",
        )

    existing_new_user = db.query(models.NewUsers).filter(models.NewUsers.email == user.email).first()
    if existing_new_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email is already in the registration queue.",
        )

    hashed_password = security.get_password_hash(user.password)
    new_user = models.NewUsers(
        name=user.name,
        email=user.email,
        state=user.state,
        county=user.county,
        district=user.district,
        school=user.school,
        phone_number=user.phone_number,
        password=hashed_password,
        role='teacher',
        report=0,
        emailed=0
    )
    db.add(new_user)
    db.commit()

    send_email(
        recipient_email=user.email,
        subject="Registration Successful",
        message=f"Dear {user.email},\n\nThank you for registering with us! Once you are validated by a fellow teacher in your district or one of us here at Homeroom Heroes, you will be able to create your profile and start receiving support.\n\nBest regards,\nHomeroom Heroes Team"
    )

    return {"message": "User registered successfully. You should receive an email shortly. Please check your spam folder"}

@router.post("/validate_user/{user_email}", status_code=status.HTTP_200_OK)
def validate_user(user_email: str, db: Session = Depends(get_db)):
    """
    Validates a new user and moves them to the registered users table.
    """
    user_to_validate = db.query(models.NewUsers).filter(models.NewUsers.email == user_email).first()

    if not user_to_validate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in the validation queue.",
        )

    new_registered_user = models.RegisteredUsers(
        email=user_to_validate.email,
        password=user_to_validate.password,
        role=user_to_validate.role,
        phone_number=user_to_validate.phone_number
    )
    db.add(new_registered_user)
    db.delete(user_to_validate)
    db.commit()

    send_email(
        recipient_email=user_to_validate.email,
        subject="Validation Notification",
        message=f"Dear {user_to_validate.email},\n\nWe are pleased to inform you that your registration with us has been successfully validated! You may now log in and create your profile to start receiving support.\n\nIf you have any questions or need assistance, please do not hesitate to contact us.\n\nBest regards,\nHomeroom Heroes Team"
    )

    return {"message": "User validated successfully."}