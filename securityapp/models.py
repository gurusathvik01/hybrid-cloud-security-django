from django.db import models

class Event(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    username = models.CharField(max_length=100)
    source_ip = models.CharField(max_length=50)
    port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    action = models.CharField(max_length=10)
    packet_size = models.FloatField()
    duration = models.FloatField()
    login_attempts = models.IntegerField()
    prediction = models.CharField(max_length=20)
    attack_type = models.CharField(max_length=50)
    score = models.FloatField()


from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'User'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    def __str__(self):
        return f"{self.user.username} ({self.role})"

from django.db import models
from django.contrib.auth.models import User
import os

def user_upload_path(instance, filename):
    """Organize uploaded files per user."""
    return os.path.join('user_uploads', instance.user.username, filename)

class SecureFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to=user_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {os.path.basename(self.file.name)}"

from django.utils import timezone

class AccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()   # <-- correct field name
    success = models.BooleanField(default=False)
    notes = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        status = "✅ Success" if self.success else "🚨 Unauthorized"
        return f"{self.user.username} → {self.file.file.name} ({status})"


from django.db import models
from django.conf import settings

class SecureFile(models.Model):
    # your existing SecureFile fields (example)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to="secure_files/")
    is_encrypted = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)

class AccessLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.file} — {self.user or 'anonymous'} @ {self.timestamp} ({'OK' if self.success else 'FAIL'})"
