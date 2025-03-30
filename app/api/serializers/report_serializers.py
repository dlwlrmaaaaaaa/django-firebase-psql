from rest_framework import serializers
from ..models import Report, Department
from datetime import datetime
from firebase_admin import storage
from app.firebase import db, bucket
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import uuid
import base64
from django.contrib.auth import get_user_model
from math import radians, sin, cos, sqrt, atan2
from django.utils.timezone import now, timedelta
from geopy.distance import geodesic
import logging
import time
import math
User = get_user_model()

DUPLICATE_RADIUS_KM = 0.05
EMERGENCY_THRESHOLD_MINUTES = 60
NON_EMERGENCY_THRESHOLD_DAYS = 2
IMAGE_UPLOAD_PATH = "images_report/"

logger = logging.getLogger(__name__)

class AddReportSerializer(serializers.ModelSerializer):
    image_path = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Report
        fields = [
            'report_id', 'type_of_report', 'report_description', 'longitude', 'latitude', 'is_emergency',
            'image_path', 'custom_type', 'floor_number', 'location', 'force_submit'
        ]

    @staticmethod
    def calculate_distance(lat1, lon1, lat2, lon2):
        """Calculate the Haversine distance between two points using math module for speed."""
        R = 6371  # Earth radius in kilometers
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def check_duplicate_reports(self, validated_data):
        """Check for duplicate reports within a certain radius and time."""
        try:
            report_lat = float(validated_data['latitude'])
            report_lon = float(validated_data['longitude'])
        except (ValueError, TypeError):
            raise serializers.ValidationError("Invalid latitude or longitude values.")

        report_type = validated_data['type_of_report']
        is_emergency = validated_data.get("is_emergency", "").lower()
        current_time = now()

        if is_emergency == "emergency":
            time_threshold = current_time - timedelta(minutes=EMERGENCY_THRESHOLD_MINUTES)
        else:
            time_threshold = current_time - timedelta(days=NON_EMERGENCY_THRESHOLD_DAYS)

        # Query Firestore for recent reports of the same type
        collection_path = "reports"
        document_id = report_type.lower()
        doc_ref = db.collection(collection_path).document(document_id)
        recent_reports = doc_ref.collection("reports").where(
            "report_date", ">=", time_threshold.isoformat()
        ).stream()

        for report in recent_reports:
            report_data = report.to_dict()
            try:
                existing_lat = float(report_data["latitude"])
                existing_lon = float(report_data["longitude"])
            except (ValueError, TypeError):
                continue  # Skip if coordinates are invalid

            if self.calculate_distance(report_lat, report_lon, existing_lat, existing_lon) <= DUPLICATE_RADIUS_KM:
                return True, report_data

        return False, None

    def validate_image_path(self, value):
        """Ensure image_path is a valid base64 string."""
        if value and not isinstance(value, str):
            raise serializers.ValidationError("Image path must be a valid string.")
        return value

    def process_image_upload(self, image_data, report_uuid):
        """Process and upload the image to Firebase."""
        if not image_data:
            return ""
        try:
            image_format, imgstr = image_data.split(";base64,")
            ext = image_format.split("/")[-1]
            image_file = ContentFile(base64.b64decode(imgstr), name=f"{report_uuid}.{ext}")
            bucket = storage.bucket()
            image_blob = bucket.blob(f"{IMAGE_UPLOAD_PATH}{report_uuid}.{ext}")
            image_blob.upload_from_file(image_file)
            image_blob.make_public()
            return image_blob.public_url
        except Exception as e:
            logger.error(f"Image upload failed: {e}")
            raise serializers.ValidationError({"detail": "Failed to upload image."})

    def create(self, validated_data):
        try:
            overall_start = time.time()
            is_duplicate, duplicate_report = self.check_duplicate_reports(validated_data)
            logger.debug(f"Duplicate check took {time.time() - overall_start:.3f} seconds.")

            user = self.context['request'].user
            force_submit = str(validated_data.get('force_submit', "false")).lower() == "true"

            if is_duplicate:
                user_ids = duplicate_report.get('user_ids', [])
                if isinstance(user_ids, str):
                    try:
                        user_ids = json.loads(user_ids)
                    except Exception:
                        raise serializers.ValidationError({
                            "detail": "Invalid 'user_ids' format in duplicate report."
                        })

                if user.id in [int(id) for id in user_ids]:
                    raise serializers.ValidationError({
                        "detail": "You've already reported or verified this incident.",
                        "existing_report": duplicate_report
                    })
                else:
                    if force_submit:
                        report_id = duplicate_report.get('report_id')
                        if not report_id:
                            raise serializers.ValidationError({
                                "detail": "The duplicate report is missing a 'report_id'.",
                                "duplicate_report": duplicate_report
                            })
                        report_count = int(duplicate_report.get('report_count', 1)) + 1
                        collection_path = 'reports'
                        document_id = validated_data['type_of_report'].lower()
                        doc_ref = db.collection(collection_path).document(document_id)
                        report_ref = doc_ref.collection('reports').document(report_id)
                        existing_report = report_ref.get()
                        if existing_report.exists:
                            existing_data = existing_report.to_dict()
                            user_ids = existing_data.get('user_ids', [])
                            if user.id not in user_ids:
                                user_ids.append(user.id)
                            usernames = existing_data.get('usernames', [])
                            if user.username not in usernames:
                                usernames.append(user.username)
                            report_ref.update({
                                'report_count': report_count,
                                'usernames': usernames,
                                'user_ids': user_ids,
                            })
                            validation_ref = report_ref.collection('validation').document(str(user.id))
                            validation_ref.set({
                                'user_id': user.id,
                                'validated': "validated",
                            })
                        validated_data['report_count'] = report_count
                        return duplicate_report
                    else:
                        raise serializers.ValidationError({
                            "detail": "A similar report already exists.",
                            "existing_report": duplicate_report
                        })

            # Process new report creation
            try:
                report_lat = float(validated_data['latitude'])
                report_lon = float(validated_data['longitude'])
            except (ValueError, TypeError):
                raise serializers.ValidationError("Invalid latitude or longitude values.")
            report_type = validated_data['type_of_report']
            current_time = datetime.now()

            report_type_to_department_id = {
                "Fire Accident": 1,
                "Flood": 6,
                "Road Accident": 3,
                "Street Light": 4,
                "Fallen Tree": 7,
                "Pothole": 5,
                "Others": 6
            }

            target_department_id = report_type_to_department_id.get(report_type)
            if not target_department_id:
                raise serializers.ValidationError({"detail": f"Unknown report type: {report_type}"})

            start_admins = time.time()
            department_admins = User.objects.filter(
                role='department_admin',
                department_id=target_department_id
            ).values('id', 'station_address', 'username')
            workers = list(User.objects.filter(
                role='worker',
                department_id=target_department_id
            ).values('id', 'station_address', 'username'))
            logger.debug(f"Fetching admins and workers took {time.time() - start_admins:.3f} seconds. Found {department_admins.count()} admins.")

            # Determine nearest admin using a list of valid candidates
            valid_admins = []
            for admin in department_admins:
                station_addr = admin.get('station_address')
                if station_addr:
                    try:
                        station_lat, station_lon = map(float, station_addr.split(','))
                        dist = self.calculate_distance(report_lat, report_lon, station_lat, station_lon)
                        valid_admins.append((admin, dist))
                    except ValueError as e:
                        logger.debug(f"Skipping admin {admin['username']} due to invalid station address: {e}")
            if valid_admins:
                nearest_admin, _ = min(valid_admins, key=lambda x: x[1])
                validated_data['assigned_to_id'] = nearest_admin['id']
                validated_data['status'] = "Ongoing"
            else:
                validated_data['assigned_to_id'] = None
                validated_data['status'] = "Pending"

            report_uuid = uuid.uuid4()
            validated_data["image_path"] = self.process_image_upload(
                validated_data.get("image_path", ""), report_uuid
            )

            report_data = {
                'report_id': str(report_uuid),
                'user_id': user.id,
                'username': user.username,
                'type_of_report': validated_data['type_of_report'],
                'report_description': validated_data['report_description'],
                'is_emergency': validated_data['is_emergency'],
                'longitude': validated_data['longitude'],
                'latitude': validated_data['latitude'],
                'location': validated_data['location'],
                'upvote': 0,
                'downvote': 0,
                'status': validated_data.get('status'),
                'report_date': current_time.isoformat(),
                'image_path': validated_data["image_path"],
                'custom_type': validated_data['custom_type'],
                'floor_number': validated_data['floor_number'],
                'is_validated': False,
                'update_date': current_time.isoformat(),
                'assigned_to_id': validated_data.get('assigned_to_id'),
                'report_count': validated_data.get('report_count', 1),
                'usernames': [validated_data.get('username', user.username)],
                'user_ids': [validated_data.get('user_id', user.id)],
                'workers': workers,
                'department_id': target_department_id,
            }

            start_batch = time.time()
            batch = db.batch()
            collection_path = 'reports'
            document_id = validated_data['type_of_report'].lower()
            doc_ref = db.collection(collection_path).document(document_id)
            batch.set(doc_ref.collection('reports').document(str(report_uuid)), report_data)
            batch.commit()
            logger.debug(f"Firestore batch commit took {time.time() - start_batch:.3f} seconds.")

            start_save = time.time()
            report = Report(
                report_id=report_uuid,
                user_id=user.id,
                image_path=validated_data["image_path"],
                type_of_report=validated_data['type_of_report'],
                report_description=validated_data['report_description'],
                is_emergency=validated_data['is_emergency'],
                longitude=validated_data['longitude'],
                latitude=validated_data['latitude'],
                location=validated_data['location'],
                upvote=0,
                downvote=0,
                status=validated_data.get('status'),
                custom_type=validated_data['custom_type'],
                floor_number=validated_data['floor_number'],
                report_date=current_time,
                assigned_to_id=validated_data.get('assigned_to_id'),
            )
            report.save()
            logger.debug(f"Report save took {time.time() - start_save:.3f} seconds.")
            return report

        except serializers.ValidationError as e:
            raise e
# import math
# import base64
# import uuid
# import time
# import json
# import io
# from datetime import datetime, timedelta
# from django.core.files.base import ContentFile
# from django.utils.timezone import now
# from PIL import Image
# import imagehash

# class AddReportSerializer(serializers.ModelSerializer):
#     image_path = serializers.CharField(required=False, allow_blank=True)

#     class Meta:
#         model = Report
#         fields = [
#             'report_id', 'type_of_report', 'report_description', 'longitude', 'latitude', 'is_emergency',
#             'image_path', 'custom_type', 'floor_number', 'location', 'force_submit'
#         ]

#     @staticmethod
#     def calculate_distance(lat1, lon1, lat2, lon2):
#         """Calculate the Haversine distance between two points using math for speed."""
#         R = 6371  # Earth radius in kilometers
#         phi1 = math.radians(lat1)
#         phi2 = math.radians(lat2)
#         dphi = math.radians(lat2 - lat1)
#         dlambda = math.radians(lon2 - lon1)
#         a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
#         c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
#         return R * c

#     def compute_image_hash(self, image_data):
#         """
#         Compute a perceptual hash of the image provided as a base64 string.
#         Expects a string in the format "data:image/xxx;base64,...."
#         """
#         try:
#             header, encoded = image_data.split(";base64,")
#             image_bytes = base64.b64decode(encoded)
#             image = Image.open(io.BytesIO(image_bytes))
#             # Using average hash; you can experiment with different methods (phash, dhash, etc.)
#             return str(imagehash.average_hash(image))
#         except Exception as e:
#             logger.debug(f"Error computing image hash: {e}")
#             return None

#     def is_similar_image_hash(self, hash1, hash2, threshold=4):
#         """
#         Compare two image hashes. Returns True if the hamming distance is within threshold.
#         """
#         try:
#             h1 = imagehash.hex_to_hash(hash1)
#             h2 = imagehash.hex_to_hash(hash2)   

#             return abs(h1 - h2) <= threshold
#         except Exception as e:
#             logger.debug(f"Error comparing image hashes: {e}")
#             return False

#     def check_duplicate_reports(self, validated_data, new_image_hash=None):
#         """
#         Check for duplicate reports based on location and image similarity.
#         If a candidate is within the DUPLICATE_RADIUS_KM, then if new_image_hash is provided
#         and the candidate has an image_hash field, perform a similarity check.
#         """
#         try:
#             report_lat = float(validated_data['latitude'])
#             report_lon = float(validated_data['longitude'])
#         except (ValueError, TypeError):
#             raise serializers.ValidationError("Invalid latitude or longitude values.")

#         report_type = validated_data['type_of_report']
#         is_emergency = validated_data.get("is_emergency", "").lower()
#         current_time = now()

#         if is_emergency == "emergency":
#             time_threshold = current_time - timedelta(minutes=EMERGENCY_THRESHOLD_MINUTES)
#         else:
#             time_threshold = current_time - timedelta(days=NON_EMERGENCY_THRESHOLD_DAYS)

#         # Query Firestore for recent reports of the same type
#         collection_path = "reports"
#         document_id = report_type.lower()
#         doc_ref = db.collection(collection_path).document(document_id)
#         recent_reports = doc_ref.collection("reports").where(
#             "report_date", ">=", time_threshold.isoformat()
#         ).stream()

#         for report in recent_reports:
#             report_data = report.to_dict()
#             try:
#                 existing_lat = float(report_data["latitude"])
#                 existing_lon = float(report_data["longitude"])
#             except (ValueError, TypeError):
#                 continue  # Skip if coordinates are invalid

#             distance = self.calculate_distance(report_lat, report_lon, existing_lat, existing_lon)
#             if distance <= DUPLICATE_RADIUS_KM:
#                 # If an image hash for the new report is available and the candidate report has one,
#                 # check if the images are similar.
#                 candidate_hash = report_data.get("image_hash")
#                 if new_image_hash and candidate_hash:
#                     if not self.is_similar_image_hash(new_image_hash, candidate_hash):
#                         continue  # Not similar enough, so not a duplicate.
#                 # If no image hash is available, fall back to the location check.
#                 return True, report_data

#         return False, None

#     def validate_image_path(self, value):
#         """Ensure image_path is a valid base64 string."""
#         if value and not isinstance(value, str):
#             raise serializers.ValidationError("Image path must be a valid string.")
#         return value

#     def process_image_upload(self, image_data, report_uuid):
#         """Process and upload the image to Firebase."""
#         if not image_data:
#             return ""
#         try:
#             image_format, imgstr = image_data.split(";base64,")
#             ext = image_format.split("/")[-1]
#             image_file = ContentFile(base64.b64decode(imgstr), name=f"{report_uuid}.{ext}")
#             bucket = storage.bucket()
#             image_blob = bucket.blob(f"{IMAGE_UPLOAD_PATH}{report_uuid}.{ext}")
#             image_blob.upload_from_file(image_file)
#             image_blob.make_public()
#             return image_blob.public_url
#         except Exception as e:
#             logger.error(f"Image upload failed: {e}")
#             raise serializers.ValidationError({"detail": "Failed to upload image."})

#     def create(self, validated_data):
#         try:
#             # Compute the new report's image hash (if image is provided)
#             new_image_data = validated_data.get("image_path", "")
#             new_image_hash = None
#             if new_image_data:
#                 new_image_hash = self.compute_image_hash(new_image_data)

#             # Check for duplicate reports using both location and image similarity.
#             is_duplicate, duplicate_report = self.check_duplicate_reports(validated_data, new_image_hash)
#             logger.debug(f"Duplicate check completed.")

#             user = self.context['request'].user
#             force_submit = str(validated_data.get('force_submit', "false")).lower() == "true"

#             if is_duplicate:
#                 user_ids = duplicate_report.get('user_ids', [])
#                 if isinstance(user_ids, str):
#                     try:
#                         user_ids = json.loads(user_ids)
#                     except Exception:
#                         raise serializers.ValidationError({
#                             "detail": "Invalid 'user_ids' format in duplicate report."
#                         })

#                 if user.id in [int(uid) for uid in user_ids]:
#                     raise serializers.ValidationError({
#                         "detail": "You've already reported or verified this incident.",
#                         "existing_report": duplicate_report
#                     })
#                 else:
#                     if force_submit:
#                         report_id = duplicate_report.get('report_id')
#                         if not report_id:
#                             raise serializers.ValidationError({
#                                 "detail": "The duplicate report is missing a 'report_id'.",
#                                 "duplicate_report": duplicate_report
#                             })
#                         report_count = int(duplicate_report.get('report_count', 1)) + 1
#                         collection_path = 'reports'
#                         document_id = validated_data['type_of_report'].lower()
#                         doc_ref = db.collection(collection_path).document(document_id)
#                         report_ref = doc_ref.collection('reports').document(report_id)
#                         existing_report = report_ref.get()
#                         if existing_report.exists:
#                             existing_data = existing_report.to_dict()
#                             user_ids = existing_data.get('user_ids', [])
#                             if user.id not in user_ids:
#                                 user_ids.append(user.id)
#                             usernames = existing_data.get('usernames', [])
#                             if user.username not in usernames:
#                                 usernames.append(user.username)
#                             report_ref.update({
#                                 'report_count': report_count,
#                                 'usernames': usernames,
#                                 'user_ids': user_ids,
#                             })
#                             validation_ref = report_ref.collection('validation').document(str(user.id))
#                             validation_ref.set({
#                                 'user_id': user.id,
#                                 'validated': "validated",
#                             })
#                         validated_data['report_count'] = report_count
#                         return duplicate_report
#                     else:
#                         raise serializers.ValidationError({
#                             "detail": "A similar report already exists.",
#                             "existing_report": duplicate_report
#                         })

#             # Process new report creation
#             try:
#                 report_lat = float(validated_data['latitude'])
#                 report_lon = float(validated_data['longitude'])
#             except (ValueError, TypeError):
#                 raise serializers.ValidationError("Invalid latitude or longitude values.")
#             report_type = validated_data['type_of_report']
#             current_time = datetime.now()

#             report_type_to_department_id = {
#                 "Fire Accident": 1,
#                 "Flood": 6,
#                 "Road Accident": 3,
#                 "Street Light": 4,
#                 "Fallen Tree": 7,
#                 "Pothole": 5,
#                 "Others": 6
#             }

#             target_department_id = report_type_to_department_id.get(report_type)
#             if not target_department_id:
#                 raise serializers.ValidationError({"detail": f"Unknown report type: {report_type}"})

#             start_admins = time.time()
#             department_admins = User.objects.filter(
#                 role='department_admin',
#                 department_id=target_department_id
#             ).values('id', 'station_address', 'username')
#             workers = list(User.objects.filter(
#                 role='worker',
#                 department_id=target_department_id
#             ).values('id', 'station_address', 'username'))
#             logger.debug(f"Fetching admins and workers took {time.time() - start_admins:.3f} seconds.")

#             # Determine nearest admin using valid station addresses
#             valid_admins = []
#             for admin in department_admins:
#                 station_addr = admin.get('station_address')
#                 if station_addr:
#                     try:
#                         station_lat, station_lon = map(float, station_addr.split(','))
#                         dist = self.calculate_distance(report_lat, report_lon, station_lat, station_lon)
#                         valid_admins.append((admin, dist))
#                     except ValueError as e:
#                         logger.debug(f"Skipping admin {admin['username']} due to invalid station address: {e}")
#             if valid_admins:
#                 nearest_admin, _ = min(valid_admins, key=lambda x: x[1])
#                 validated_data['assigned_to_id'] = nearest_admin['id']
#                 validated_data['status'] = "Ongoing"
#             else:
#                 validated_data['assigned_to_id'] = None
#                 validated_data['status'] = "Pending"

#             report_uuid = uuid.uuid4()
#             # Process image upload and store public URL
#             validated_data["image_path"] = self.process_image_upload(
#                 new_image_data, report_uuid
#             )
#             # Include the computed image hash in report_data for future comparisons.
#             report_data = {
#                 'report_id': str(report_uuid),
#                 'user_id': user.id,
#                 'username': user.username,
#                 'type_of_report': validated_data['type_of_report'],
#                 'report_description': validated_data['report_description'],
#                 'is_emergency': validated_data['is_emergency'],
#                 'longitude': validated_data['longitude'],
#                 'latitude': validated_data['latitude'],
#                 'location': validated_data['location'],
#                 'upvote': 0,
#                 'downvote': 0,
#                 'status': validated_data.get('status'),
#                 'report_date': current_time.isoformat(),
#                 'image_path': validated_data["image_path"],
#                 'custom_type': validated_data['custom_type'],
#                 'floor_number': validated_data['floor_number'],
#                 'is_validated': False,
#                 'update_date': current_time.isoformat(),
#                 'assigned_to_id': validated_data.get('assigned_to_id'),
#                 'report_count': validated_data.get('report_count', 1),
#                 'usernames': [validated_data.get('username', user.username)],
#                 'user_ids': [validated_data.get('user_id', user.id)],
#                 'workers': workers,
#                 'department_id': target_department_id,
#                 # Store image_hash to compare with future reports
#                 'image_hash': new_image_hash,
#             }

#             start_batch = time.time()
#             batch = db.batch()
#             collection_path = 'reports'
#             document_id = validated_data['type_of_report'].lower()
#             doc_ref = db.collection(collection_path).document(document_id)
#             batch.set(doc_ref.collection('reports').document(str(report_uuid)), report_data)
#             batch.commit()
#             logger.debug(f"Firestore batch commit took {time.time() - start_batch:.3f} seconds.")

#             start_save = time.time()
#             report = Report(
#                 report_id=report_uuid,
#                 user_id=user.id,
#                 image_path=validated_data["image_path"],
#                 type_of_report=validated_data['type_of_report'],
#                 report_description=validated_data['report_description'],
#                 is_emergency=validated_data['is_emergency'],
#                 longitude=validated_data['longitude'],
#                 latitude=validated_data['latitude'],
#                 location=validated_data['location'],
#                 upvote=0,
#                 downvote=0,
#                 status=validated_data.get('status'),
#                 custom_type=validated_data['custom_type'],
#                 floor_number=validated_data['floor_number'],
#                 report_date=current_time,
#                 assigned_to_id=validated_data.get('assigned_to_id'),
#             )
#             report.save()
#             logger.debug(f"Report save took {time.time() - start_save:.3f} seconds.")
#             return report

#         except serializers.ValidationError as e:
#             raise e

class UpdateReportSerializer(serializers.ModelSerializer):
       
       class Meta:
            model = Report
            fields = ['type_of_report', 'report_description', 'is_emergency']
      
       def update(self, instance, validated_data):
             request = self.context.get('request')
             user = request.user 
             if instance.user == user or user.role.lower() == 'citizen':
                return super().update(instance, validated_data)
             else:
                raise serializers.ValidationError("You are not authorized to update this report.")



     


             
        

      
        
    