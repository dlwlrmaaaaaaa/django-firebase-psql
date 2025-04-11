import firebase_admin
import json
from firebase_admin import credentials, storage, firestore
import os
import base64

# Decode the base64-encoded service account JSON
encoded = os.getenv("GOOGLE_SERVICE_BASE64")
decoded_json = json.loads(base64.b64decode(encoded))

# Use the decoded credentials directly
cred = credentials.Certificate(decoded_json)

# Initialize Firebase if not already initialized
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'crisp-63736.appspot.com',
        'databaseURL': 'https://crisp-914b8-default-rtdb.asia-southeast1.firebasedatabase.app/'
    })

# Get Firestore and Storage clients
db = firestore.client()
bucket = storage.bucket()
