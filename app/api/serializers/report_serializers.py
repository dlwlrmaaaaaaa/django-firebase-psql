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
        fields = ['type_of_report', 'report_description', 'longitude', 'latitude', 'category', 'image_path']
    
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
                image_name = str(uuid.uuid4())  # Generate unique image name

                # Decode base64 data and create ContentFile for the image
                image_file = ContentFile(base64.b64decode(imgstr), name=f"{image_name}.{ext}")
                
                # Save the image to a temporary path
                temp_image_path = default_storage.save(f'temporary_path/{image_name}.{ext}', image_file)

                # Get a reference to the Firebase storage bucket
                bucket = storage.bucket()

                # Create a blob and upload the file to Firebase
                image_blob = bucket.blob(f'images_report/{image_name}.{ext}')
                image_blob.upload_from_filename(temp_image_path, content_type=f'image/{ext}')

                # Make the image publicly accessible
                image_blob.make_public()

                # Add the image URL to report data
                image_path_string = image_blob.public_url
                print(image_blob.public_url)

            report_data = {
                'report_id': str(report_uuid),
                'username': user.username,                   
                'type_of_report': validated_data['type_of_report'],
                'report_description': validated_data['report_description'],
                'category': validated_data['category'],
                'longitude': validated_data['longitude'],
                'latitude': validated_data['latitude'],
                'upvote': 0,
                'downvote': 0,
                'status': "Pending",
                'report_date': datetime.now().isoformat(),
                'image_path': image_path_string,
            }
            # Add the report to Firestore
            db.collection('reports').add(report_data)

            # Save the report in the database
            report = Report(
                report_id=report_uuid,
                user_id=user.id,
                username=user.username,
                image_path=image_path_string,
                type_of_report=validated_data['type_of_report'],
                report_description=validated_data['report_description'],
                category=validated_data['category'],
                longitude=validated_data['longitude'],
                latitude=validated_data['latitude'],
                upvote=0,
                downvote=0,
                status="Pending",
                report_date=datetime.now()
            )
            report.save()

            return report
        
        except Exception as e:
            print(f'An exception occurred: {e}')
            raise serializers.ValidationError({"detail": "Failed to create the report due to an internal error."})
    

class UpdateReportSerializer(serializers.ModelSerializer):
       
       class Meta:
            model = Report
            fields = ['type_of_report', 'report_description', 'category']
      
       def update(self, instance, validated_data):
             request = self.context.get('request')
             user = request.user 
             if instance.user == user or user.role.lower() == 'citizen':
                return super().update(instance, validated_data)
             else:
                raise serializers.ValidationError("You are not authorized to update this report.")


     


             
        

      
        
    