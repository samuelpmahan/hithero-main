import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

def send_email(recipient_email: str, subject: str, message: str):
    """
    Sends an email using SendGrid.
    """
    sender = 'homeroom.heroes.contact@gmail.com'
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient_email
    msg.attach(MIMEText(message, 'plain'))

    smtp_server = 'smtp.sendgrid.net'
    smtp_port = 465

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as smtp:
            smtp.login('apikey', settings.SENDGRID_API_KEY)
            smtp.send_message(msg)
    except Exception as e:
        # In a real application, you would log this error
        print(f'Error sending email: {e}')