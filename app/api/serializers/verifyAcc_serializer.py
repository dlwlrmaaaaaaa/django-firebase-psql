from rest_framework import serializers
from ..models import VerifyAccount
from datetime import datetime
from firebase_admin import storage
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from app.firebase import db
import uuid
import base64

class VerifyAccountSerializer(serializers.ModelSerializer):
    photo_image_path = serializers.CharField(required=False, allow_blank=True)
    id_selfie_image_path = serializers.CharField(required=False, allow_blank=True)
    id_picture_image_path = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = VerifyAccount
        fields = [
            'first_name', 
            'middle_name', 
            'last_name', 
            'text_address', 
            # 'birthday', 
            'id_number', 
            'photo_image_path', 
            'id_selfie_image_path', 
            'id_picture_image_path'
        ]

    def validate_photo_image_path(self, value):
        if value and not isinstance(value, str):
            raise serializers.ValidationError("Photo image path must be a valid string.")
        return value

    def validate_id_selfie_image_path(self, value):
        if value and not isinstance(value, str):
            raise serializers.ValidationError("ID selfie image path must be a valid string.")
        return value

    def validate_id_picture_image_path(self, value):
        if value and not isinstance(value, str):
            raise serializers.ValidationError("ID picture image path must be a valid string.")
        return value

    def create(self, validated_data):
        try:
            user = self.context['request'].user
            verification_uuid = uuid.uuid4()

            image_paths = {}

            # Process each image path if present
            for image_field in ['photo_image_path', 'id_selfie_image_path', 'id_picture_image_path']:
                if image_field in validated_data and validated_data[image_field]:
                    image_data = validated_data[image_field]
                    image_format, imgstr = image_data.split(';base64,')
                    ext = image_format.split('/')[-1]
                    image_name = str(uuid.uuid4())

                    # Decode base64 data and create ContentFile for the image
                    image_file = ContentFile(base64.b64decode(imgstr), name=f"{image_name}.{ext}")
                    
                    # Save the image to a temporary path
                    temp_image_path = default_storage.save(f'temporary_path/{image_name}.{ext}', image_file)

                    # Upload to Firebase
                    bucket = storage.bucket()
                    image_blob = bucket.blob(f'verification_images/{image_name}.{ext}')
                    image_blob.upload_from_filename(temp_image_path, content_type=f'image/{ext}')
                    image_blob.make_public()

                    # Store public URL
                    image_paths[image_field] = image_blob.public_url

            verify_account_data = {
                'user': user.id,  # Store only the user ID
                'first_name': validated_data.get('first_name'),
                'middle_name': validated_data.get('middle_name'),
                'last_name': validated_data.get('last_name'),
                'text_address': validated_data.get('text_address'),
                'id_number': validated_data.get('id_number'),
                'is_account_verified': False,  # Default to False
                'photo_image_path': image_paths.get('photo_image_path'),
                'id_selfie_image_path': image_paths.get('id_selfie_image_path'),
                'id_picture_image_path': image_paths.get('id_picture_image_path'),
                'verify_date': datetime.now().isoformat(),
            }

            # Add the verification data to Firestore
            db.collection('verifyAccount').add(verify_account_data)

            # Create a new VerifyAccount instance
            verify_account = VerifyAccount(
                user=user,
                first_name=validated_data.get('first_name'),
                middle_name=validated_data.get('middle_name'),
                last_name=validated_data.get('last_name'),
                text_address=validated_data.get('text_address'),
                id_number=validated_data.get('id_number'),
                is_account_verified=False,
                photo_image_path=image_paths.get('photo_image_path'),
                id_selfie_image_path=image_paths.get('id_selfie_image_path'),
                id_picture_image_path=image_paths.get('id_picture_image_path'),
            )
            verify_account.save()

            return verify_account

        except Exception as e:
            print(f'An exception occurred: {e}')
            raise serializers.ValidationError({"detail": "Failed to create the verification account due to an internal error."})