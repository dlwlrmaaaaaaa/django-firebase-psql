import firebase_admin
from firebase_admin import credentials, storage, firestore

# Initialize Firebase
# cred = credentials.Certificate('C:/Users/ADMIN/Documents/crisp-5d09f-firebase-adminsdk-vl4cg-30e5cb1ca3.json')
cred = credentials.Certificate('C:/Users/codin/OneDrive/crisp-63736-firebase-adminsdk-r1i8j-a043e2e3ad.json')


if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'crisp-63736.appspot.com',
        'databaseURL': 'https://crisp-914b8-default-rtdb.asia-southeast1.firebasedatabase.app/'
    })


db = firestore.client()
bucket = storage.bucket()