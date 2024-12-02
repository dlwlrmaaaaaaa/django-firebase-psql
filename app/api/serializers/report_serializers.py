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
        fields = ['report_id','type_of_report', 'report_description', 'longitude', 'latitude', 'is_emergency', 'image_path', 'custom_type', 'floor_number', 'location', 'force_submit']

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
        time_threshold = datetime.now() - timedelta(minutes=60)

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
            user = self.context['request'].user
            force_submit = validated_data.get('force_submit', "false")
            print("FORECE_SUBMIT: ", validated_data.get('force_submit'))
            force_submit = str(force_submit).lower() == "true"
            if is_duplicate:
                # Check if the same user submitted the report
                user_ids = duplicate_report.get('user_ids', [])
                if isinstance(user_ids, str):
                    try:
                        # Convert string representation of list into a proper list
                        user_ids = eval(user_ids)
                    except:
                        raise serializers.ValidationError({
                            "detail": "Invalid 'user_ids' format in duplicate report."
                        })
                
                if user.id in [int(id) for id in user_ids]:
                    raise serializers.ValidationError({
                        "detail": "You've already reported this incident.",
                        "existing_report": duplicate_report
                    })
                else:
                    # Handle forced submission for duplicates
                    if force_submit:
                        report_id = duplicate_report.get('report_id')
                        if not report_id:
                            raise serializers.ValidationError({
                                "detail": "The duplicate report is missing a 'report_id'.",
                                "duplicate_report": duplicate_report
                            })
                        
                        # Increment the report count
                        report_count = int(duplicate_report.get('report_count', 1)) + 1
                        collection_path = 'reports'
                        document_id = validated_data['type_of_report'].lower()

                        try:
                            doc_ref = db.collection(collection_path).document(document_id)
                            report_ref = doc_ref.collection('reports').document(report_id)

                            # Fetch the existing report to append user_id
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

                            validated_data['report_count'] = report_count
                            return duplicate_report

                        except Exception as e:
                            raise serializers.ValidationError({
                                "detail": "Failed to update the existing report in Firestore.",
                                "error": str(e)
                            })
                    else:
                        raise serializers.ValidationError({
                            "detail": "A similar report already exists.",
                            "existing_report": duplicate_report
                        })

                
            report_uuid = uuid.uuid4()
            image_path_string = ''
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
                'status': "Pending",
                'report_date': datetime.now().isoformat(),
                'image_path': image_path_string,
                'custom_type': validated_data['custom_type'],
                'floor_number': validated_data['floor_number'],
                'is_validated': False,
                'update_date': datetime.now().isoformat(),
                'assigned_to_id': validated_data.get('assigned_id'),
                'report_count': validated_data.get('report_count', 1),
                'usernames': [validated_data.get('username', user.username)],
                'user_ids': [validated_data.get('user_id', user.id)]
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
            print(report)
            return report
        except serializers.ValidationError as e:
            raise e
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



     


             
        

      
        
    