from django.contrib import admin
from django.utils.html import format_html
from .models import Event

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp", "username", "source_ip", 
        "attack_type", "prediction", "score", 
        "ai_solution", "download_pdf"
    )

    def ai_solution(self, obj):
        if obj.prediction == "Attack":
            return format_html(f'<a href="/admin/ai_solution/{obj.id}/" style="color:green;">View Solution</a>')
        return "Normal"

    ai_solution.short_description = "Gemini AI Solution"

    def download_pdf(self, obj):
        if obj.prediction == "Attack":
            return format_html(f'<a href="/admin/download_pdf/{obj.id}/" style="color:blue;">📄 Download PDF</a>')
        return "—"

    download_pdf.short_description = "Prevention Report"


from django.contrib import admin
from .models import SecureFile, AccessLog

@admin.register(SecureFile)
class SecureFileAdmin(admin.ModelAdmin):
    list_display = ("id", "file", "user", "is_encrypted", "uploaded_at")
    search_fields = ("file", "user__username")

@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "file", "ip_address", "timestamp", "success")
    list_filter = ("success", "timestamp")
    search_fields = ("user__username", "file__file", "ip_address", "notes")
