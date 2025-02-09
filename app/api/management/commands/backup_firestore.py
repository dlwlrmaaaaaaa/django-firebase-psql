from app.firebase import db
import json
import firebase_admin
from firebase_admin import credentials, firestore
from django.core.management.base import BaseCommand
import datetime
import os

def serialize_data(data):
    """ Convert Firestore data to JSON serializable format """
    if isinstance(data, dict):
        return {k: serialize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_data(v) for v in data]
    elif hasattr(data, "isoformat"):  # Convert Firestore timestamps
        return data.isoformat()
    else:
        return data
    
class Command(BaseCommand):
    help = "Backup Firestore data to a JSON file"

    def handle(self, *args, **kwargs):
        collections = db.collections()
        backup_data = {}

        for collection in collections:
            docs = collection.stream()
            backup_data[collection.id] = {
                doc.id: serialize_data(doc.to_dict()) for doc in docs
            }

        # Ensure backup directory exists
        backup_dir = "backup"
        os.makedirs(backup_dir, exist_ok=True)

        # Generate timestamped filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"firestore_backup_{timestamp}.json"

        with open(os.path.join(backup_dir, filename), "w") as f:
            json.dump(backup_data, f, indent=4)

        self.stdout.write(self.style.SUCCESS(f"Firestore backup saved as '{backup_dir}/{filename}'"))