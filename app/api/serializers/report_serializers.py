from rest_framework import serializers
from ..models import Report
from datetime import datetime
from firebase_admin import storage
from app.firebase import db, bucket
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from app.firebase import db
import uuid



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
        user = self.context['request'].user
        report_uuid = uuid.uuid4()
        report_data = {
                    'report_id': str(report_uuid),
                    'user_id': user.id,                   
                    'type_of_report': validated_data['type_of_report'],
                    'report_description': validated_data['report_description'],
                    'category': validated_data['category'],
                    'longitude': validated_data['longitude'],
                    'latitude': validated_data['latitude'],
                    'upvote': 0,
                    'status': "Pending",
                    'report_date': datetime.now().isoformat()
                }
        request = self.context['request']
        if 'image' in request.FILES:
                    image_file = request.FILES['image']
                    image_name = str(uuid.uuid4())  # Generate unique image name

                    # Save the image to a temporary path
                    temp_image_path = default_storage.save(f'temporary_path/{image_name}', ContentFile(image_file.read()))

                    # Get a reference to the Firebase storage bucket
                    bucket = storage.bucket()

                    # Create a blob and upload the file to Firebase
                    image_blob = bucket.blob(f'images_report/{image_name}')
                    image_blob.upload_from_filename(temp_image_path, content_type=image_file.content_type)

                    # Make the image publicly accessible
                    image_blob.make_public()

                    # Add the image URL to report data
                    image_path_string = image_blob.public_url

         # Add the report to Firestore
        db.collection('reports').add(report_data)
        
        # Save the report in the database // this not include the firebase
        report = Report(
            report_id=report_uuid,
            user_id=user.id,
            image_path=image_path_string,
            type_of_report=validated_data['type_of_report'],
            report_description=validated_data['report_description'],
            category=validated_data['category'],
            longitude=validated_data['longitude'],
            latitude=validated_data['latitude'],
            upvote=0,
            status="Pending",
            report_date=datetime.now()
        )
        report.save()
        return report
    

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


# class DeleteReportSerializer(serializers.ModelSerializer):



             
        

      
        
    