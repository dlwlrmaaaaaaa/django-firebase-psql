import firebase_admin
import json
from firebase_admin import credentials, storage, firestore
import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent  # Adjust based on folder structure
FIREBASE_KEY_PATH = BASE_DIR / "app" / "config" / "crisp-63736-firebase-adminsdk-r1i8j-4f63ef8ace.json"

cred = credentials.Certificate(str(FIREBASE_KEY_PATH))

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'crisp-63736.appspot.com',
        'databaseURL': 'https://crisp-914b8-default-rtdb.asia-southeast1.firebasedatabase.app/'
    })


db = firestore.client()
bucket = storage.bucket()