from rest_framework import serializers
from ..models import Report, Department
from datetime import datetime
from firebase_admin import storage
from app.firebase import db, bucket
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from app.firebase import db
import uuid
import base64
from django.contrib.auth import get_user_model
from math import radians, sin, cos, sqrt, atan2
from django.utils.timezone import now, timedelta

User = get_user_model()

class AddReportSerializer(serializers.ModelSerializer):
    image_path = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Report
        fields = ['type_of_report', 'report_description', 'longitude', 'latitude', 'is_emergency', 'image_path', 'custom_type', 'floor_number', 'location']

    @staticmethod
    def calculate_distance(lat1, lon1, lat2, lon2):
        """Calculate the Haversine distance between two points."""
        R = 6371  # Earth's radius in kilometers
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
        c = 2 * atan2(sqrt(a), sqrt(1 - a))
        return R * c

    def check_duplicate_reports(self, validated_data):
        """Check for duplicate reports within a certain radius and time."""
        report_lat = float(validated_data['latitude'])
        report_lon = float(validated_data['longitude'])
        report_type = validated_data['type_of_report']
        time_threshold = datetime.now() - timedelta(minutes=30)

        # Query Firestore for recent reports of the same type
        collection_path = 'reports'
        document_id = report_type.lower()
        doc_ref = db.collection(collection_path).document(document_id)
        recent_reports = doc_ref.collection('reports').where(
            'report_date', '>=', time_threshold.isoformat()
        ).stream()

        for report in recent_reports:
            report_data = report.to_dict()
            existing_lat = float(report_data['latitude'])
            existing_lon = float(report_data['longitude'])

            # Calculate distance to detect duplicates
            distance = self.calculate_distance(report_lat, report_lon, existing_lat, existing_lon)
            if distance <= 0.5:  # 0.5 km radius
                return True, {
                    key: str(value) for key, value in report_data.items()
                }

        return False, None

    def validate_image_path(self, value):
        """Ensure image_path is a valid base64 string."""
        if value and not isinstance(value, str):
            raise serializers.ValidationError("Image path must be a valid string.")
        return value

    def create(self, validated_data):
        try:
            is_duplicate, duplicate_report = self.check_duplicate_reports(validated_data)
            print(f"Duplicate Check - is_duplicate: {is_duplicate}, duplicate_report: {duplicate_report}")

            if is_duplicate:
                raise serializers.ValidationError({
                    "detail": "A similar report already exists.",
                    "existing_report": duplicate_report
                })

            # Ensure required fields are present
            if not all(key in validated_data for key in ['type_of_report', 'latitude', 'longitude']):
                raise serializers.ValidationError("Missing required fields in the request.")

            user = self.context['request'].user
            report_uuid = uuid.uuid4()
            image_path_string = ''

            if validated_data['is_emergency'] == 'emergency':
                report_lat = float(validated_data['latitude'])
                report_lon = float(validated_data['longitude'])
                report_type = validated_data['type_of_report']

                report_type_to_department_id = {
                    "Fires": 1, 
                    "Medical": 2,
                    "Police": 3,
                    "Street lights": 4,
                    "Potholes": 5,
                }

                target_department_id = report_type_to_department_id.get(report_type)

                if not target_department_id:
                    raise serializers.ValidationError({"detail": f"Unknown report type: {report_type}"})

                department_admins = User.objects.filter(
                    role='department_admin',
                    department_id=target_department_id
                )

                nearest_admin = None
                min_distance = float('inf')

                for admin in department_admins:
                    if admin.station_address:  # Ensure the admin has station coordinates
                        try:
                            station_lat, station_lon = map(float, admin.station_address.split(','))
                        except ValueError:
                            raise serializers.ValidationError({"detail": "Invalid station_address format. Expected 'latitude,longitude'."})

                        distance = self.calculate_distance(report_lat, report_lon, station_lat, station_lon)

                        if distance < min_distance:
                            min_distance = distance
                            nearest_admin = admin

                if nearest_admin:
                    validated_data['assigned_id'] = nearest_admin.id

            # Check for the image_path (base64 string)
            if 'image_path' in validated_data and validated_data['image_path']:
                image_data = validated_data['image_path']
                image_format, imgstr = image_data.split(';base64,')  # Splitting the format
                ext = image_format.split('/')[-1]  # Getting the file extension

                # Use the report UUID as the image name
                image_name = str(report_uuid)

                # Decode base64 data and create ContentFile for the image
                image_file = ContentFile(base64.b64decode(imgstr), name=f"{image_name}.{ext}")

                # Save the image to a temporary path
                temp_image_path = default_storage.save(f'temporary_path/{image_name}.{ext}', image_file)

                # Get a reference to the Firebase storage bucket
                bucket = storage.bucket()

                # Create a blob using the report UUID as the image name and upload the file to Firebase
                image_blob = bucket.blob(f'images_report/{image_name}.{ext}')
                image_blob.upload_from_filename(temp_image_path, content_type=f'image/{ext}')

                # Make the image publicly accessible
                image_blob.make_public()

                # Add the public image URL to report data
                image_path_string = image_blob.public_url

            report_data = {
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
                'status': "Pending",
                'report_date': datetime.now().isoformat(),
                'image_path': image_path_string,
                'custom_type': validated_data['custom_type'],
                'floor_number': validated_data['floor_number'],
                'is_validated': False,
                'update_date': datetime.now().isoformat(),     
                'assigned_to_id': validated_data.get('assigned_id'),         
            }

            # Add the report to Firestore
            collection_path = 'reports'
            document_id = validated_data['type_of_report'].lower()         
            try:
                doc_ref = db.collection(collection_path).document(document_id)
                doc_ref.collection('reports').document(str(report_uuid)).set(report_data)
            except Exception as e:
                print(f"Error adding report to Firestore: {e}")
                raise e

            # Save the report in the database
            report = Report(
                report_id=report_uuid,
                user_id=user.id,
                image_path=image_path_string,
                type_of_report=validated_data['type_of_report'],
                report_description=validated_data['report_description'],
                is_emergency=validated_data['is_emergency'],
                longitude=validated_data['longitude'],
                latitude=validated_data['latitude'],
                location=validated_data['location'],
                upvote=0,
                downvote=0,
                status="Pending",
                custom_type=validated_data['custom_type'],
                floor_number=validated_data['floor_number'],
                report_date=datetime.now(),
                assigned_to_id=validated_data.get('assigned_id'),       
            )
            report.save()

            return report
        except serializers.ValidationError as e:
            # Catch the ValidationError and raise it again to ensure the message is sent back to the frontend
            raise e
        except Exception as e:
            print(f'An exception occurred: {e}')
            raise serializers.ValidationError({"detail": "Failed to create the report due to an internal error."})
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



     


             
        

      
        
    