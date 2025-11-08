import boto3
from botocore.exceptions import ClientError
from django.conf import settings
import os


class S3Service:
    """
    Service for handling AWS S3 operations including presigned URLs
    """

    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        self.bucket_name = settings.S3_BUCKET
        self.cdn_base_url = settings.CDN_BASE_URL

    def generate_presigned_upload_url(self, key: str, content_type: str, expires_in: int = 300):
        """
        Generate a presigned URL for uploading a file to S3

        Args:
            key: The S3 object key (path/filename)
            content_type: The MIME type of the file
            expires_in: URL expiration time in seconds (default: 300 = 5 minutes)

        Returns:
            dict: Contains uploadUrl (presigned URL), publicUrl (CDN URL), and key
        """
        try:
            # Generate presigned URL for PUT operation
            upload_url = self.s3_client.generate_presigned_url(
                'put_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': key,
                    'ContentType': content_type,
                },
                ExpiresIn=expires_in
            )

            # Generate public URL using CDN base
            public_url = f"{self.cdn_base_url}/{key}"

            return {
                'key': key,
                'uploadUrl': upload_url,
                'publicUrl': public_url
            }
        except ClientError as e:
            raise Exception(f"Error generating presigned URL: {str(e)}")

    def delete_file(self, key: str):
        """
        Delete a file from S3

        Args:
            key: The S3 object key to delete
        """
        try:
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=key
            )
        except ClientError as e:
            raise Exception(f"Error deleting file from S3: {str(e)}")
