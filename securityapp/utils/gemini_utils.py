import os
import google.generativeai as genai


# Load Gemini API key
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_KEY_HERE")

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("✅ Gemini API initialized successfully")
    except Exception as e:
        print(f"⚠️ Gemini API initialization failed: {e}")
else:
    print("⚠️ Gemini API key missing — AI suggestions disabled.")


def get_gemini_suggestions(event_data):
    """
    Generate AI-based prevention and solution suggestions for a detected attack.
    """
    if not GEMINI_API_KEY:
        return "⚠️ Gemini API key not configured."

    prompt = f"""
You are a cybersecurity analyst. A network intrusion has been detected with the following details:

Attack Type: {event_data.get('attack_type')}
Prediction: {event_data.get('prediction')}
Source IP: {event_data.get('source_ip')}
Port: {event_data.get('port')}
Protocol: {event_data.get('protocol')}
Action: {event_data.get('action')}
Packet Size: {event_data.get('packet_size')} bytes
Duration: {event_data.get('duration')} seconds
Login Attempts: {event_data.get('login_attempts')}
Confidence Score: {event_data.get('score') if event_data.get('score') is not None else 0.0:.2f}


Provide a detailed but concise report including:
1️⃣ The nature of this attack.  
2️⃣ Possible reasons or vulnerabilities causing it.  
3️⃣ 5–7 actionable prevention or mitigation steps.  
4️⃣ One long-term recommendation to strengthen the cloud security system.
    """

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text or "⚠️ No response from Gemini model."
    except Exception as e:
        return f"⚠️ Error fetching Gemini AI response: {e}"
