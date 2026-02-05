from django import forms
from .models import SecureFile

class SecureFileForm(forms.ModelForm):
    class Meta:
        model = SecureFile
        fields = ['file']
