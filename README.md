# Upwind Email Shield 🛡️
### A real-time Gmail Add-on that leverages a multi-layered defense model to analyze opened emails, delivering a maliciousness score and a clear, explainable security verdict.

## 🧠 Security Logic & Core Features

The system evaluates each email through a strict, rule-based pipeline:

### 1. SQLite Blacklist Engine (Priority Check)
Before external APIs are queried, the system checks the sender's address against a local **SQLite** database. 
* If a match is found in the manually managed blacklist, the scan terminates immediately, assigns a **100/100 Threat Score**, and flags the email as `Blacklisted`.

### 2. Google Safe Browsing Integration
The system extracts all URLs from the email body and verifies them against Google's global threat database. Any known malicious link results in an immediate **100/100 Threat Score**.

### 3. Domain Maturity (RDAP Protocol)
Analyzes the sender's domain age to detect freshly registered "look-alike" domains commonly used in phishing campaigns.
* **Domain < 4 days old:** +90 points (Critical)
* **Domain < 30 days old:** +50 points (Suspicious)
* **Established domains:** 0 points

### 4. Heuristic Analysis
Scans the subject and body for aggressive social engineering keywords (e.g., "Urgent", "Action Required") and suspicious call-to-action phrases.

---

## 🧪 Testing the System (Demo Mode)
To demonstrate the system's "High Risk" UI and response logic:
1. Send an email to the connected Gmail account with the word **"DEMO"** in the subject line.
2. Open the email and trigger the Add-on.
3. The backend will intercept the keyword, simulate a 0-day-old malicious domain, and return a **90/100 High Risk** verdict with red visual indicators and a direct link to Upwind's security resources.

---

### 💡 Engineering Note: RDAP vs. WHOIS
* **RDAP over WHOIS:** I migrated from traditional WHOIS to RDAP for domain checks. RDAP returns clean JSON and is much more stable on cloud platforms (like Render), avoiding the rate limits and connection drops common with legacy WHOIS servers.
* **Demo Environment (Blacklist):** The local SQLite blacklist is kept empty for this demo. Normally, if a sender is blacklisted, the scan stops immediately and returns a 100 score. Keeping it empty allows you to see the rest of the analysis engine (RDAP, Google APIs, Heuristics) at work.

## 🛠️ Tech Stack
* **Backend:** Python 3.9+, FastAPI (Deployed on Render)
* **Database:** SQLite (Lightweight, local database for Blacklist and Scan Logging)
* **Frontend:** Google Apps Script (Gmail Add-on SDK)
* **External APIs:** RDAP Protocol, Google Safe Browsing API

## ⚙️ Installation & Setup

### 1. Backend Setup (FastAPI & SQLite)
The backend is built with FastAPI and uses a local SQLite database for the blacklist and logging. 

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
   cd YOUR_REPO_NAME
   ```

2. **Install dependencies:**
   It is recommended to use a virtual environment.
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables:**
   Create a `.env` file in the root directory. You will need a Google Safe Browsing API key:
   ```env
   GOOGLE_API_KEY=your_google_api_key_here
   ```

4. **Run the local server:**
   ```bash
   uvicorn main:app --reload
   ```
   *(Note: The live demo of this project is deployed on Render. Local execution is only required for development or local testing).*

### 2. Frontend Setup (Gmail Add-on)
The frontend is a Google Apps Script that connects directly to the Gmail UI.

1. Go to [Google Apps Script](https://script.google.com/) and create a new project.
2. Clear the default code and paste the contents of the provided `app_script` code (e.g., `Code.gs`).
3. **Important:** Locate the API endpoint variable in the script and update it to point to your live Render backend URL (or your `ngrok` URL if testing locally).
4. Click **Deploy** -> **Test Deployments**.
5. Select **Application: Gmail** and click **Install**. The Add-on will now appear in your Gmail sidebar when you open an email.
