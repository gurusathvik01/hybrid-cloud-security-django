import os
from fpdf import FPDF
from django.conf import settings
from securityapp.utils.gemini_utils import get_gemini_suggestions

def generate_prevention_pdf(event):
    """Generate a Prevention Report PDF for the given Event instance."""
    event_data = {
        "Event ID": event.id,
        "Timestamp": event.timestamp.isoformat(),
        "Username": event.username,
        "Source IP": event.source_ip,
        "Port": event.port,
        "Protocol": event.protocol,
        "Action": event.action,
        "Packet Size": event.packet_size,
        "Duration": event.duration,
        "Login Attempts": event.login_attempts,
        "Prediction": event.prediction,
        "Attack Type": event.attack_type,
        "Score": event.score,
    }

    # Get AI suggestions from Gemini
    suggestion_text = get_gemini_suggestions(event_data)

    pdf = FPDF()
    pdf.add_page()

    # ✅ Use Unicode-safe font
    font_path = os.path.join(settings.BASE_DIR, "securityapp", "static", "DejaVuSans.ttf")
    if os.path.exists(font_path):
        pdf.add_font("DejaVu", "", font_path, uni=True)
        pdf.set_font("DejaVu", "", 12)
    else:
        pdf.set_font("Arial", "", 12)

    pdf.cell(0, 10, "🛡️ IDS Prevention Report", ln=True, align="C")
    pdf.ln(8)

    pdf.set_font("DejaVu" if os.path.exists(font_path) else "Arial", 'B', 12)
    pdf.cell(0, 8, f"Event ID: {event.id}", ln=True)
    pdf.ln(4)

    pdf.set_font("DejaVu" if os.path.exists(font_path) else "Arial", '', 11)
    for key, value in event_data.items():
        pdf.cell(0, 7, f"{key}: {value}", ln=True)

    pdf.ln(5)
    pdf.set_font("DejaVu" if os.path.exists(font_path) else "Arial", 'B', 13)
    pdf.cell(0, 8, "AI-Powered Prevention Suggestions:", ln=True)
    pdf.ln(4)

    pdf.set_font("DejaVu" if os.path.exists(font_path) else "Arial", '', 11)
    pdf.multi_cell(0, 6, suggestion_text)

    # Save to temporary file
    filename = f"prevention_report_{event.id}.pdf"
    file_path = os.path.join(settings.BASE_DIR, filename)
    pdf.output(file_path)

    return file_path
