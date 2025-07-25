from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.orm import Session
import random

from app.apis.v1 import schemas
from app.db import models
from app.db.session import SessionLocal

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/create_teacher_profile/", status_code=status.HTTP_201_CREATED)
def create_teacher_profile(
    profile: schemas.TeacherProfileCreate,
    db: Session = Depends(get_db),
    # In a real app, you'd get the current user from the token
    # current_user: models.RegisteredUsers = Depends(get_current_user)
):
    """
    Creates a new teacher profile.
    """
    # Simplified: In a real app, you'd get the user ID from the token
    # For now, we'll just use a placeholder
    user_id = 1

    existing_profile = db.query(models.TeacherList).filter(models.TeacherList.regUserID == user_id).first()
    if existing_profile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A profile for this user already exists.",
        )

    aa_link = profile.wishlist + "&tag=h0mer00mher0-20"
    
    email = "test@example.com" # Placeholder
    first_part_email = email.split('@')[0]
    random_number = random.randint(1, 9999)
    auto_url_id = f"{first_part_email}{random_number}"
    while db.query(models.TeacherList).filter(models.TeacherList.url_id == auto_url_id).first():
        random_number = random.randint(1, 9999)
        auto_url_id = f"{first_part_email}{random_number}"

    new_profile = models.TeacherList(
        name=profile.name,
        state=profile.state,
        county=profile.county,
        district=profile.district,
        school=profile.school,
        regUserID=user_id,
        about_me=profile.aboutMe,
        wishlist_url=aa_link,
        url_id=auto_url_id
    )

    db.add(new_profile)
    db.commit()

    return {"message": "Teacher profile created successfully."}