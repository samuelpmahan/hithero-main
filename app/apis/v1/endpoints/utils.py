from fastapi import APIRouter, Depends, HTTPException, status, Form, Request, Response
from sqlalchemy.orm import Session

from app.db import models
from app.db.session import SessionLocal
from app.services.email_service import send_email
from app.services.recaptcha_service import verify_recaptcha
from typing import List

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post('/contact_us/', status_code=status.HTTP_200_OK)
async def contact_us(
    name: str = Form(...),
    email: str = Form(...),
    subject: str = Form(...),
    message: str = Form(...),
    recaptcha_response: str = Form(...)
):
    """
    Handles the 'Contact Us' form submission.
    """
    if not verify_recaptcha(recaptcha_response):
        raise HTTPException(status_code=400, detail="Invalid reCAPTCHA")
    
    full_message = f"From: {name} ({email})\n\n{message}"
    send_email(
        recipient_email='Homeroom.heroes.contact@gmail.com', # Should be a config variable
        subject=subject,
        message=full_message
    )
    return {"message": "Your message has been sent successfully!"}

@router.get("/get_states/", response_model=List[str])
def get_states(db: Session = Depends(get_db)):
    """
    Retrieves a distinct list of states from the schools table.
    """
    states = db.query(models.School.state).distinct().all()
    return sorted([state[0] for state in states])

@router.get("/get_counties/{state}", response_model=List[str])
def get_counties(state: str, db: Session = Depends(get_db)):
    """
    Retrieves a distinct list of counties for a given state.
    """
    counties = db.query(models.School.county).filter(models.School.state == state).distinct().all()
    if not counties:
        return []
    return sorted([county[0] for county in counties])

# ... (similar endpoints for get_districts and get_schools) ...

@router.get("/promo/{token}")
async def get_promotional_page(request: Request, token: str, response: Response):
    """
    Sets a session cookie for a promotional campaign and redirects to the homepage.
    """
    # This logic can be expanded based on your needs
    # For now, we'll just set the token in the session
    request.session["promo_token"] = token
    response.status_code = status.HTTP_307_TEMPORARY_REDIRECT
    response.headers["Location"] = "/pages/homepage.html"
    return response

@router.get("/get_promo_info/")
async def get_promo_info(request: Request):
    """
    API for the frontend to fetch and clear promotional info from the session.
    """
    promo_token = request.session.pop("promo_token", None)
    if promo_token:
        # Here you could look up promo details in a database or config file
        return {"promo_title": f"Special Promotion: {promo_token}!", "promo_image_url": f"/static/images/promo/{promo_token}.png"}
    return {}