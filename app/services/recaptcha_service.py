import requests

from app.core.config import settings

def verify_recaptcha(recaptcha_response: str) -> bool:
    """
    Verifies the reCAPTCHA response with Google's servers.
    """
    url = "https://www.google.com/recaptcha/api/siteverify"
    params = {"secret": settings.SERVER_KEY_CAPTCHA, "response": recaptcha_response}
    response = requests.post(url, params=params)
    data = response.json()
    return data.get("success", False)