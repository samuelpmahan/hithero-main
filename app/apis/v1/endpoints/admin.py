from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.orm import Session

from app.db import models
from app.db.session import SessionLocal
from app.services.email_service import send_email, send_attachment
from app.core.security import get_current_user # This would be a new dependency to get the authenticated user
import os

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Note: In a real application, each of these endpoints would have a dependency
# like `current_user: models.RegisteredUsers = Depends(get_current_user)`
# and then check `if current_user.role != 'admin': ...` to secure the endpoint.

@router.post("/delete_user/{user_email}", status_code=status.HTTP_200_OK)
def delete_user(user_email: str, db: Session = Depends(get_db)):
    """
    Deletes a user from the new_users validation queue.
    (Admin only)
    """
    user_to_delete = db.query(models.NewUsers).filter(models.NewUsers.email == user_email).first()

    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in validation queue.",
        )

    db.delete(user_to_delete)
    db.commit()
    return {"message": f"User '{user_email}' has been successfully deleted from the validation queue."}


@router.post("/report_user/{user_email}", status_code=status.HTTP_200_OK)
def report_user(user_email: str, db: Session = Depends(get_db)):
    """
    Marks a user in the validation queue as reported.
    (Can be used by teachers, but the management is an admin task)
    """
    user_to_report = db.query(models.NewUsers).filter(models.NewUsers.email == user_email).first()

    if not user_to_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in validation queue.",
        )

    user_to_report.report = 1
    db.commit()
    return {"message": f"User '{user_email}' has been successfully reported."}


@router.post("/emailed_user/{user_email}", status_code=status.HTTP_200_OK)
def emailed_user(user_email: str, db: Session = Depends(get_db)):
    """
    Marks that an email has been sent to a user in the validation queue.
    (Admin only)
    """
    user_to_update = db.query(models.NewUsers).filter(models.NewUsers.email == user_email).first()

    if not user_to_update:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in validation queue.",
        )

    user_to_update.emailed = True
    db.commit()
    return {"message": f"User '{user_email}' marked as emailed."}


@router.post("/generate_teacher_report/", status_code=status.HTTP_200_OK)
def generate_teacher_report(
    state: str = Form(...),
    county: str = Form(None),
    district: str = Form(None),
    school: str = Form(None),
    db: Session = Depends(get_db)
):
    """
    Generates a teacher report and emails it.
    (Admin only)
    """
    query = db.query(models.TeacherList.name, models.TeacherList.school, models.TeacherList.regUserID)
    
    # Apply filters
    if state:
        query = query.filter(models.TeacherList.state == state)
    if county:
        query = query.filter(models.TeacherList.county == county)
    if district:
        query = query.filter(models.TeacherList.district == district)
    if school:
        query = query.filter(models.TeacherList.school == school)

    teachers = query.all()

    if not teachers:
        raise HTTPException(status_code=404, detail="No teachers found with the specified criteria.")

    reg_user_ids = [teacher.regUserID for teacher in teachers]
    users = db.query(models.RegisteredUsers.id, models.RegisteredUsers.email, models.RegisteredUsers.phone_number).filter(models.RegisteredUsers.id.in_(reg_user_ids)).all()
    user_dict = {user.id: {"email": user.email, "phone": user.phone_number} for user in users}

    report_data = ["Name\tSchool\tEmail\tPhone"]
    for teacher in teachers:
        user_info = user_dict.get(teacher.regUserID, {})
        report_data.append(f"{teacher.name}\t{teacher.school}\t{user_info.get('email', 'N/A')}\t{user_info.get('phone', 'N/A')}")
    
    file_content = "\n".join(report_data)
    file_path = './teacher_report.txt'

    with open(file_path, 'w') as temp_file:
        temp_file.write(file_content)

    send_attachment(
        recipient_email="homeroom.heroes.main@gmail.com", # Should be a configurable admin email
        subject="Teacher Report",
        message="Please find the attached teacher report.",
        attachment_path=file_path
    )
    
    # Clean up the created file
    os.remove(file_path)

    return {"message": "Teacher report generated and sent successfully."}