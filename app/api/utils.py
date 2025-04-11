from django.contrib.auth import get_user_model
from firebase_admin import auth
import requests
import json
import logging
import google.auth.transport.requests
from google.oauth2 import service_account
from django.http import JsonResponse
from django.contrib.auth import get_user_model
User = get_user_model()
from api.models import ExpoPushToken
logger = logging.getLogger(__name__)

from django.conf import settings
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent  # Adjust based on folder structure
FIREBASE_KEY_PATH = BASE_DIR / "app" / "config" / "crisp-63736-firebase-adminsdk-r1i8j-4889c57ed1.json"


def generate_firebase_token(user):
    additional_claims = {
        "role": user.role,  
    }
    return auth.create_custom_token(str(user.id), additional_claims)

def get_account_type(user):
    return user.role  # Ensure this is accessed from the correct user mode
FCM_ENDPOINT = "https://fcm.googleapis.com/v1/projects/crisp-63736/messages:send"

EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send"

creds = service_account.Credentials.from_service_account_file(
    str(FIREBASE_KEY_PATH),
    scopes=["https://www.googleapis.com/auth/firebase.messaging"]
)
def get_access_token():
    """Refresh and return a valid OAuth 2.0 access token."""
    request = google.auth.transport.requests.Request()
    creds.refresh(request)  # Refresh token
    return creds.token
def send_push_notification(expo_push_token, title, message, data=None):
    """
    Sends a push notification using Expo's push notification service.
    """
    access_token = get_access_token()
    payload = {
        "message": {
            "token": expo_push_token,  # Correct field name for single device
            "notification": {
                "title": title,
                "body": message
            },
            "data": data or {}  # Optional custom data
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Accept-encoding": "gzip, deflate",
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        response = requests.post(FCM_ENDPOINT, data=json.dumps(payload), headers=headers)
        response_data = response.json()
        # print("FCM Response:", response.status_code, response.json())

        if response.status_code == 200:
            return JsonResponse({"success": "Notification sent successfully!"}, status=200)
        else:
            return JsonResponse({"error":  "Notification failed"}, status=response.status_code)
    except Exception as e:
        logger.error(f"Error sending push notification: {str(e)}")
        return False

def send_push_notification_to_all(title, message):
    """
    Sends a push notification to all users with stored FCM tokens.
    """
    users = ExpoPushToken.objects.exclude(expo_push_token__isnull=True).exclude(expo_push_token="")
    access_token = get_access_token()

    if not users.exists():
        return JsonResponse({"error": "No registered push tokens found"}, status=400)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    responses = []
    
    for user in users:
        payload = {
            "message": {
                "token": user.expo_push_token,
                "notification": {
                    "title": title,
                    "body": message
                }
            }
        }

        try:
            response = requests.post(FCM_ENDPOINT, json=payload, headers=headers)
            response_data = response.json()
            responses.append({"token": user.expo_push_token, "status": response.status_code, "response": response_data})
        except Exception as e:
            responses.append({"token": user.expo_push_token, "error": str(e)})

    return JsonResponse({"responses": responses}, status=200)