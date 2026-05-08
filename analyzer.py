import os
import re
import requests
import whois
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# המפתח שלך (בהמשך נלמד להסתיר אותו)
API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"


def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)


# הפונקציה שפונה למודיעין של גוגל
def check_urls_with_google(urls):
    if not urls:
        return False

    # בונים את המבנה שגוגל מצפה לקבל
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls]  # מכניס את כל הלינקים שמצאנו
        }
    }

    try:
        response = requests.post(GOOGLE_API_URL, json=payload)
        response.raise_for_status()
        data = response.json()

        # שורת הדיבאג החדשה שלך:
        print(f"[*] Google Response: {data}")

        if "matches" in data:
            print(f"[!] Google Safe Browsing Alert: Found {len(data['matches'])} threats!")
            return True
        return False

    except Exception as e:
        print(f"[-] Error connecting to Google API: {e}")
        return False


def get_domain_age_info(domain_name):
    """בודק את גיל הדומיין באמצעות פרוטוקול RDAP המודרני"""
    # אם קיבלת אימייל שלם במקום רק דומיין, ננקה אותו
    if "@" in domain_name:
        domain_name = domain_name.split('@')[-1]

    domain_name = domain_name.lower().strip()
    rdap_url = f"https://rdap.org/domain/{domain_name}"

    try:
        # פנייה לשרת ה-RDAP (עובד מעל HTTP, ולכן פחות נחסם ב-Render)
        response = requests.get(rdap_url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            events = data.get('events', [])

            for event in events:
                # אנחנו מחפשים את אירוע הרישום (registration)
                if event.get('action') == 'registration':
                    reg_date_str = event.get('eventDate')
                    # המרה של פורמט התאריך (לוקחים רק את ה-10 תווים הראשונים YYYY-MM-DD)
                    reg_date = datetime.strptime(reg_date_str[:10], '%Y-%m-%d')
                    age_days = (datetime.now() - reg_date).days

                    # הלוגיקה המחמירה שלך
                    if age_days <= 4:
                        return 90, f"Critical: Domain is only {age_days} days old"
                    elif age_days <= 30:
                        return 50, f"Suspicious: Domain is {age_days} days old"

                    return 0, f"Domain age: {age_days} days"

        # אם השרת החזיר תשובה אבל אין בה תאריך רישום ברור
        return 20, "Domain exists but age not confirmed"

    except Exception as e:
        # אם יש שגיאת תקשורת או שהדומיין לא נמצא
        print(f"RDAP Error for {domain_name}: {e}")
        return 60, "Could not verify domain age (Potentially new or private)"


def analyze_email_content(sender, subject, body):
    score = 0
    reasons = []  # <--- הוספנו את רשימת הסיבות!
    subject_lower = subject.lower()
    body_lower = body.lower()

    # --- שכבת המודיעין: בדיקה מול גוגל ---
    found_urls = extract_urls(body_lower)
    if found_urls:
        print(f"[*] Found URLs to analyze: {found_urls}")
        is_malicious = check_urls_with_google(found_urls)
        if is_malicious:
            print("[!!!] URL flagged as DANGEROUS by Google!")
            score += 100
            reasons.append("Contains a known malicious link (Google Safe Browsing)")

    try:
        # מחלצים את הדומיין מכתובת המייל
        domain = sender.split("@")[-1].strip(">").strip()

        # --- מילת הקסם למצגת ---
        if "demo" in subject_lower or "דמו" in subject_lower:
            age_risk = 90
            age_desc = "Critical: Domain is only 0 days old (Simulated)"
        else:
            age_risk, age_desc = get_domain_age_info(domain)
        # -----------------------

        if age_risk > 0:
            print(f"[*] Domain Age Check: {age_desc} (+{age_risk} points)")
            score += age_risk
            reasons.append(age_desc)  # שומרים את הסיבה

    except Exception as e:
        print(f"[-] Domain analysis failed: {e}")
        pass

    # --- השכבה ההיוריסטית: מילים וסיומות (מורחב ומוכן) ---

    # 1. סיומות דומיין בעייתיות
    shady_extensions = [".xyz", ".top", ".ru", ".cn", ".biz", ".info"]
    if any(ext in sender.lower() for ext in shady_extensions):
        score += 30
        reasons.append("Sender uses a highly suspicious domain extension")

    # 2. מילות לחץ בנושא המייל
    urgent_subject_words = ["urgent", "password", "suspended", "action required", "alert", "invoice", "payment failed"]
    if any(word in subject_lower for word in urgent_subject_words):
        score += 20
        reasons.append("Subject contains aggressive/urgent phishing keywords")

    # 3. קריאה לפעולה חשודה בגוף המייל
    phishing_calls_to_action = ["click here", "login to your account", "verify your account", "update your details"]
    if any(phrase in body_lower for phrase in phishing_calls_to_action):
        score += 20
        reasons.append("Body contains suspicious requests for user action")

    # --- סיכום ---
    score = min(score, 100)

    if score >= 70:
        verdict = "High Risk"
    elif score >= 30:
        verdict = "Medium Risk"
    else:
        verdict = "Safe"
        reasons.append("No suspicious indicators found")  # אם הכל בסדר, נכתוב שהכל נקי

    return {"score": score, "verdict": verdict, "reasons": reasons}