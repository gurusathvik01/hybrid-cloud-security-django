import google.generativeai as genai
from django.conf import settings

genai.configure(api_key=settings.GEMINI_API_KEY)

def get_gemini_suggestions(event_data):
    prompt = f"""
    You are a cybersecurity expert. A network intrusion has been detected:
    Attack Type: {event_data['attack_type']}
    ...
    Give 5 actionable prevention steps.
    """
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text or "No suggestions received."
