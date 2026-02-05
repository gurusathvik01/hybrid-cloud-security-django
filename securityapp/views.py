import tempfile
from django.http import FileResponse, HttpResponseForbidden
from .forms import SecureFileForm
from .models import SecureFile
from .utils.crypto_utils import encrypt_file, decrypt_file
from .utils.cloud_utils import upload_to_cloud  


import os
from io import BytesIO
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import FileResponse, HttpResponse
from django.conf import settings
from django.db.models import Count
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from PyPDF2 import PdfReader, PdfWriter
from fpdf import FPDF

from .models import Event, UserProfile
from .utils.ml_utils import prepare_features, predict_attack
from .utils.alerts import send_attack_alert_email
from .utils.gemini_utils import get_gemini_suggestions


# -------------------------------
# User Landing / IDS Detection Page
# -------------------------------
def user_page(request):
    """Landing page where a user can submit data for detection."""
    if request.method == "POST":
        data = request.POST
        username = data.get("username", "anonymous")
        features = prepare_features(data)
        source_ip = request.META.get("REMOTE_ADDR")
        pred_label, attack_type, score = predict_attack(features)

        # Save event
        Event.objects.create(
            username=username,
            source_ip=source_ip,
            port=features[0],
            protocol="TCP" if features[1] == 1 else "UDP",
            action="ACCEPT" if features[2] == 1 else "DROP",
            packet_size=features[3],
            duration=features[4],
            login_attempts=features[5],
            prediction=pred_label,
            attack_type=attack_type,
            score=score,
        )

        # Alert email if attack detected
        if pred_label == "Attack":
            send_attack_alert_email({
                "username": username,
                "source_ip": source_ip,
                "attack_type": attack_type,
                "score": score,
            })

        messages.success(request, f"{pred_label} - {attack_type}")
        return redirect("user_page")

    return render(request, "index.html")


# -------------------------------
# Role-based Dashboards
# -------------------------------

from django.contrib.auth.decorators import login_required
from .models import UserProfile

@login_required
def dashboard_redirect(request):
    # Automatically create profile if missing
    profile, created = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={'role': 'admin' if request.user.is_staff else 'user'}
    )

    # Redirect based on role
    if profile.role == 'admin':
        return redirect('admin_dashboard')
    else:
        return redirect('user_dashboard')



from .models import AccessLog

from django.db.models import Count, Q

from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.shortcuts import render
from .models import Event, AccessLog


@login_required
def admin_dashboard(request):
    """
    Admin Dashboard
    ----------------
    Displays:
    - Intrusion detection (AI/IDS) events
    - Attack type summary
    - File access activity (authorized & unauthorized)
    - File access summary chart
    """

    # 🧠 1️⃣ Fetch all intrusion/attack events (AI predictions)
    events = Event.objects.all().order_by("-timestamp")

    # 📊 2️⃣ Summarize attack types for chart visualization
    attack_summary = list(
        Event.objects.values("attack_type")
        .annotate(count=Count("attack_type"))
        .order_by("-count")
    )

    # 📂 3️⃣ Fetch both authorized & unauthorized access logs
    access_logs = AccessLog.objects.all().order_by("-timestamp")[:30]

    # 📈 4️⃣ File Access Summary counts
    file_log_summary = {
        "Authorized": AccessLog.objects.filter(success=True).count(),
        "Unauthorized": AccessLog.objects.filter(success=False, notes__icontains="unauthorized").count(),
        "Errors": AccessLog.objects.filter(success=False, notes__icontains="error").count(),
        "Missing": AccessLog.objects.filter(success=False, notes__icontains="missing").count(),
    }

    # 🧾 5️⃣ Breakdown for better filtering (optional)
    success_logs = AccessLog.objects.filter(success=True).order_by("-timestamp")[:10]
    unauthorized_logs = AccessLog.objects.filter(success=False, notes__icontains="unauthorized").order_by("-timestamp")[:10]
    error_logs = AccessLog.objects.filter(success=False, notes__icontains="error").order_by("-timestamp")[:10]

    # ✅ 6️⃣ Render template with all sections
    return render(request, "dashboard_admin.html", {
        "events": events,
        "attack_summary": attack_summary,
        "access_logs": access_logs,
        "file_log_summary": file_log_summary,
        "success_logs": success_logs,
        "unauthorized_logs": unauthorized_logs,
        "error_logs": error_logs,
    })






@login_required
def user_dashboard(request):
    """User dashboard — allows secure file upload, encryption, and hybrid backup."""
    user = request.user
    files = SecureFile.objects.filter(user=user)

    if request.method == "POST":
        form = SecureFileForm(request.POST, request.FILES)
        if form.is_valid():
            secure_file = form.save(commit=False)
            secure_file.user = user
            secure_file.save()

            # 🔐 Encrypt uploaded file
            original_path = secure_file.file.path
            encrypted_path = encrypt_file(original_path)

            # Update the model to point to encrypted file
            secure_file.file.name = encrypted_path.split("media/")[-1]
            secure_file.is_encrypted = True
            secure_file.save()

            # ☁️ Optional: Hybrid cloud backup
            upload_to_cloud(encrypted_path)

            messages.success(request, "✅ File uploaded and encrypted securely.")
            return redirect("user_dashboard")
    else:
        form = SecureFileForm()

    return render(request, "dashboard_user.html", {
        "form": form,
        "files": files
    })



# -------------------------------
# AI-Powered Solution Viewer
# -------------------------------
@login_required
def ai_solution_view(request, event_id):
    """Display Gemini-generated suggestions for a specific attack event."""
    event = get_object_or_404(Event, id=event_id)
    event_data = {
        "attack_type": event.attack_type,
        "prediction": event.prediction,
        "source_ip": event.source_ip,
        "port": event.port,
        "protocol": event.protocol,
        "action": event.action,
        "packet_size": event.packet_size,
        "duration": event.duration,
        "login_attempts": event.login_attempts,
        "score": event.score,
    }

    suggestion = get_gemini_suggestions(event_data)
    return render(request, "ai_solution.html", {"event": event, "suggestion": suggestion})


# -------------------------------
# PDF Download (AI-enhanced Report)
# -------------------------------
@login_required
def download_prevention_pdf(request, event_id):
    """Generate AI-enriched Prevention Report PDF."""
    event = Event.objects.get(id=event_id)

    event_data = {
        "attack_type": event.attack_type,
        "prediction": event.prediction,
        "source_ip": event.source_ip,
        "port": event.port,
        "protocol": event.protocol,
        "action": event.action,
        "packet_size": event.packet_size,
        "duration": event.duration,
        "login_attempts": event.login_attempts,
        "score": event.score or 0.0,
    }

    # ✅ Get Gemini AI insights
    try:
        ai_text = get_gemini_suggestions(event_data)
    except Exception as e:
        ai_text = f"⚠️ AI analysis unavailable: {e}"

    # ✅ Load base PDF
    base_pdf_path = os.path.join(settings.BASE_DIR, "securityapp", "static", "reports", "base_report.pdf")
    if not os.path.exists(base_pdf_path):
        return HttpResponse("Base PDF missing.", status=404)

    reader = PdfReader(base_pdf_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    # ✅ Create overlay page
    pdf_overlay = FPDF()
    pdf_overlay.add_page()
    font_path = os.path.join(settings.BASE_DIR, "securityapp", "static", "DejaVuSans.ttf")
    if os.path.exists(font_path):
        pdf_overlay.add_font("DejaVu", "", font_path, uni=True)
        pdf_overlay.set_font("DejaVu", "", 12)
    else:
        pdf_overlay.set_font("Arial", "", 12)
    pdf_overlay.cell(0, 10, "🤖 AI-Powered Prevention Suggestions", ln=True)
    pdf_overlay.ln(5)
    pdf_overlay.multi_cell(0, 8, ai_text)

    overlay_stream = BytesIO()
    pdf_overlay.output(overlay_stream)
    overlay_stream.seek(0)
    overlay_reader = PdfReader(overlay_stream)
    writer.add_page(overlay_reader.pages[0])

    output_stream = BytesIO()
    writer.write(output_stream)
    output_stream.seek(0)
    filename = f"Prevention_Report_{event.id}.pdf"
    return FileResponse(output_stream, as_attachment=True, filename=filename)


# -------------------------------
# Authentication (Signup, Login, Logout)
# -------------------------------
def signup_view(request):
    """Register a new normal user only (no admin signup)."""
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Always assign 'user' role
            UserProfile.objects.create(user=user, role="user")
            login(request, user)
            messages.success(request, "Account created successfully.")
            return redirect("user_dashboard")
    else:
        form = UserCreationForm()
    return render(request, "auth/signup.html", {"form": form})


def login_view(request):
    """Login for existing users."""
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("dashboard_redirect")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, "auth/login.html", {"form": form})


def logout_view(request):
    """Logout current user."""
    logout(request)
    return redirect("login_selection")

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import UserProfile

def login_selection_view(request):
    return render(request, "auth/login_selection.html")


def admin_login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_staff:
            login(request, user)
            UserProfile.objects.get_or_create(user=user, defaults={"role": "admin"})
            return redirect("admin_dashboard")
        else:
            messages.error(request, "Invalid admin credentials.")
    return render(request, "auth/admin_login.html")


def user_login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None and not user.is_staff:
            login(request, user)
            UserProfile.objects.get_or_create(user=user, defaults={"role": "user"})
            return redirect("user_dashboard")
        else:
            messages.error(request, "Invalid user credentials.")
    return render(request, "auth/user_login.html")


from django.utils import timezone
from django.http import FileResponse, HttpResponseForbidden
from .models import SecureFile, AccessLog
from .utils.crypto_utils import decrypt_file
from .utils.alerts import send_attack_alert_email
import tempfile, os

from django.shortcuts import get_object_or_404
from django.http import FileResponse, HttpResponseForbidden
from .models import SecureFile, AccessLog
import tempfile, os

from django.shortcuts import get_object_or_404
from django.http import FileResponse, HttpResponseForbidden, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import SecureFile, AccessLog
from .utils.crypto_utils import decrypt_file
from .utils.alerts import send_attack_alert_email
import tempfile, os


# securityapp/views.py (relevant imports)
import os
import tempfile
from django.shortcuts import get_object_or_404
from django.http import FileResponse, HttpResponseForbidden, HttpResponse
from django.contrib.auth.decorators import login_required
from .models import SecureFile, AccessLog
from .utils.crypto_utils import decrypt_file
from .utils.alerts import send_attack_alert_email

@login_required
def access_file(request, file_id):
    """
    Serve a decrypted file **only** to its owner.
    - Logs every attempt in AccessLog (success / failure).
    - Sends alert email to security team on unauthorized attempts.
    """
    file_obj = get_object_or_404(SecureFile, id=file_id)
    ip = request.META.get("REMOTE_ADDR", "unknown")
    user = request.user

    # Case: unauthorized attempt
    if file_obj.user != user:
        AccessLog.objects.create(
            user=user if user.is_authenticated else None,
            file=file_obj,
            ip_address=ip,
            success=False,
            notes="Unauthorized access attempt: user tried to access another user's file"
        )

        # 🚨 Send alert email to security team (no user alerts)
        send_attack_alert_email({
            "attacker_username": user.username if user.is_authenticated else "anonymous",
            "attacker_ip": ip,
            "file_name": os.path.basename(file_obj.file.name),
            "file_id": file_obj.id,
            "attack_type": "Unauthorized File Access",
            "score": 0.95,
            "notes": "User attempted to open another user's file"
        })

        return HttpResponseForbidden("🚫 Unauthorized Access Logged and Reported!")

    # Case: authorized - decrypt and serve
    try:
        enc_path = file_obj.file.path
        if not os.path.exists(enc_path):
            AccessLog.objects.create(
                user=user,
                file=file_obj,
                ip_address=ip,
                success=False,
                notes="Encrypted file missing from storage"
            )
            return HttpResponse("File not found on server.", status=404)

        tmp_dir = tempfile.gettempdir()
        decrypted_filename = os.path.basename(enc_path).replace(".enc", "")
        decrypted_path = os.path.join(tmp_dir, decrypted_filename)

        # Decrypt file before serving
        decrypt_file(enc_path, decrypted_path)

        AccessLog.objects.create(
            user=user,
            file=file_obj,
            ip_address=ip,
            success=True,
            notes="Authorized download"
        )

        return FileResponse(
            open(decrypted_path, "rb"),
            as_attachment=True,
            filename=os.path.basename(decrypted_path)
        )
    except Exception as e:
        AccessLog.objects.create(
            user=user,
            file=file_obj,
            ip_address=ip,
            success=False,
            notes=f"Error while decrypting/serving file: {e}"
        )
        return HttpResponse("Error while processing file.", status=500)


@login_required
def file_system_view(request):
    """Show user-specific files securely with hybrid cloud protection."""
    user = request.user
    files = SecureFile.objects.filter(user=user).order_by("-uploaded_at")

    return render(request, "file_system.html", {
        "files": files
    })
