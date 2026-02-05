import os
import shutil
from django.conf import settings

def upload_to_cloud(file_path):
    """
    Simulates uploading an encrypted file to a cloud directory.
    Used to represent the 'public cloud' part of hybrid storage.
    """
    # Ensure cloud storage path exists
    cloud_dir = os.path.join(settings.BASE_DIR, "media", "cloud_storage")
    os.makedirs(cloud_dir, exist_ok=True)

    # Copy the encrypted file to cloud folder
    if os.path.exists(file_path):
        cloud_copy = os.path.join(cloud_dir, os.path.basename(file_path))
        shutil.copy(file_path, cloud_copy)
        print(f"☁️ File backed up to hybrid cloud: {cloud_copy}")
        return cloud_copy
    else:
        print(f"⚠️ File not found for cloud backup: {file_path}")
        return None
