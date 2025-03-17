import firebase_admin
import json
from firebase_admin import credentials, storage, firestore
import os
# Initialize Firebase
# cred = credentials.Certificate('C:/Users/ADMIN/Documents/crisp-5d09f-firebase-adminsdk-vl4cg-30e5cb1ca3.json')
# cred = credentials.Certificate('C:/Users/ADMIN/Documents/crisp-5d09f-firebase-adminsdk-vl4cg-30e5cb1ca3.json')
# cred = credentials.Certificate('C:/Users/Siyan/Desktop/Projects/Thesis-BSCS/crisp-63736-firebase-adminsdk-r1i8j-a043e2e3ad.json')
# cred = credentials.Certificate('C:/Users/Dan Edward/Documents/crisp-63736-firebase-adminsdk-r1i8j-a043e2e3ad.json')
cred = credentials.Certificate('C:/Users/cmate/Downloads/crisp-63736-firebase-adminsdk-r1i8j-a043e2e3ad.json')
# cred_data = json.loads(os.environ.get("FIREBASE_CRED"))
# cred = credentials.Certificate(cred_data)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'crisp-63736.appspot.com',
        'databaseURL': 'https://crisp-914b8-default-rtdb.asia-southeast1.firebasedatabase.app/'
    })


db = firestore.client()
bucket = storage.bucket()