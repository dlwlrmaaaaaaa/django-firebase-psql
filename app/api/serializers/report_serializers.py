from rest_framework import serializers
from ..models import Report
from datetime import datetime
from firebase_admin import storage
from app.firebase import db, bucket
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from app.firebase import db
import uuid
import base64


class AddReportSerializer(serializers.ModelSerializer):
    image_path = serializers.CharField(required=False, allow_blank=True)
    class Meta: 
        model = Report
        fields = ['type_of_report', 'report_description', 'longitude', 'latitude', 'is_emergency', 'image_path', 'custom_type', 'floor_number']
    
    def validate_image_path(self, value):
            if value and not isinstance(value, str):
                raise serializers.ValidationError("Image path must be a valid string.")
            return value
    def create(self, validated_data):
        try:
            # Get the current user and generate a report UUID
            user = self.context['request'].user
            report_uuid = uuid.uuid4()
            image_path_string = ''
            
            # Prepare the basic report data
            

            # Check for the image_path (base64 string)
            if 'image_path' in validated_data and validated_data['image_path']:
                # Extract base64 data from the image_path
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
                print(image_blob.public_url)

            report_data = {
                'user_id': user.id,  
                'username': user.username,                 
                'type_of_report': validated_data['type_of_report'],
                'report_description': validated_data['report_description'],
                'is_emergency': validated_data['is_emergency'],
                'longitude': validated_data['longitude'],
                'latitude': validated_data['latitude'],
                'upvote': 0,
                'downvote': 0,
                'status': "Pending",
                'report_date': datetime.now().isoformat(),
                'image_path': image_path_string,
                'custom_type': validated_data['custom_type'],
                'floor_number': validated_data['floor_number'],
                'is_validated': False,
                'update_date': datetime.now().isoformat(),
            }
            # Add the report to Firestore
            collection_path = 'reports'
            document_id = validated_data['type_of_report'].lower()         
            try:
                doc_ref = db.collection(collection_path).document(document_id)
                doc_ref.collection('reports').document(str(report_uuid)).set(report_data)
                doc_ref.collection('votes')
                print(f"Report successfully added to {document_id}/reports/{report_uuid}.")
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
                upvote=0,
                downvote=0,
                status="Pending",
                custom_type=validated_data['custom_type'],
                floor_number=validated_data['floor_number'],
                report_date=datetime.now()
            )
            print(report)
            report.save()

            return report
        
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


     


             
        

      
        
    