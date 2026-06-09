import streamlit as st
import google.generativeai as genai
import requests
import urllib.parse
from datetime import datetime

# 1. Configure the Web Page Layout
st.set_page_config(page_title="🛡️ ShieldAI: Open-Source Link Investigator", layout="centered")
st.title("🛡️ ShieldAI: Autonomous Link Investigator")
st.write("Analyze a live link or safely paste raw server logs/headers to discover its true structural intent.")

# ==========================================
# ⚠️ SECURITY DISCLAIMER & SAFETY BANNER
# ==========================================
st.warning(
    "⚠️ **IMPORTANT SECURITY NOTICE & DISCLAIMER**\n\n"
    "This tool is designed for educational, informational, and preliminary incident response analysis only. "
    "While it uses advanced AI threat intelligence to detect infrastructure anomalies, **no automated scanner is 100% accurate.** "
    "Clever threat actors constantly modify their infrastructure to evade detection. "
    "Always exercise caution: **never** enter passwords, sensitive personal details, or financial credentials on "
    "untrusted sites, regardless of this tool's assessment. Use of this software is entirely at your own risk."
)

# ==========================================
# 🤝 TRANSPARENCY, PRIVACY & TRUST PANEL
# ==========================================
with st.expander("🤝 How does ShieldAI protect my privacy? (Layman's Explanation)"):
    st.markdown(
        "### We designed this tool to be completely transparent and safe for you to use:\n\n"
        "1. **Your IP Address is Invisible:** When you scan a link, our server acts as a digital shield. "
        "The suspicious website only sees a neutral cloud computing network—**your personal device, home location, and real identity are never exposed** to the target.\n"
        "2. **We Don't Track You:** ShieldAI does not use tracking cookies, account logins, or user databases. "
        "Your scans are completely private and processed in real time.\n"
        "3. **Completely Open Source (Apache 2.0):** Our entire blueprint is completely public! "
        "Anyone in the world can inspect our exact code to verify that it handles data securely and contains no hidden malicious agendas.\n"
        "4. **AI-Powered Diagnostics:** We pipe the raw technical data into Google's Gemini engine to translate "
        "complex code into clear security assessments, helping you make informed safety decisions instantly."
    )

st.divider()

# 2. Helper Functions for New Threat Signals
def get_domain_age(url_string):
    """Fetches domain registration date using free open RDAP protocol."""
    try:
        parsed_url = urllib.parse.urlparse(url_string)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if ":" in domain:
            domain = domain.split(':')[0]
        if domain.startswith("www."):
            domain = domain[4:]
            
        rdap_url = f"https://rdap.org/domain/{domain}"
        res = requests.get(rdap_url, timeout=3)
        if res.status_code == 200:
            data = res.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    reg_date_str = event.get("eventDate")
                    reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                    age_days = (datetime.now() - reg_date).days
                    return reg_date.strftime("%B %d, %Y"), age_days
    except Exception:
        pass
    return None, None

# 3. Securely Initialize Gemini API
API_KEY = st.secrets.get("GEMINI_API_KEY")

if not API_KEY:
    st.error("Missing Gemini API Key. Please configure it in your platform settings.")
else:
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel('gemini-3.5-flash')

    # 4. Choose Input Type
    analysis_mode = st.radio("Choose Investigation Method:", ("Scan a Live Link Anonymously", "Paste Raw Logs / Headers Safely"))

    raw_headers = None
    target_domain_for_report = ""
    redirect_chain_data = []

    if analysis_mode == "Scan a Live Link Anonymously":
        user_url = st.text_input("Enter the suspicious URL to investigate:", placeholder="example.com")
        if st.button("Investigate Link Safely"):
            if not user_url:
                st.warning("Please enter a URL first.")
            else:
                if not user_url.startswith(('http://', 'https://')):
                    target_url = 'https://' + user_url
                else:
                    target_url = user_url
                
                target_domain_for_report = target_url

                with st.spinner("Analyzing redirect chains and capturing headers..."):
                    try:
                        headers_payload = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        response = requests.get(target_url, headers=headers_payload, timeout=7, allow_redirects=True)
                        
                        if response.history:
                            for idx, hop in enumerate(response.history):
                                redirect_chain_data.append(f"↪️ Hop {idx+1}: {hop.url} (Status: {hop.status_code})")
                        
                        redirect_chain_data.append(f"🏁 Final Destination: {response.url} (Status: {response.status_code})")
                        target_domain_for_report = response.url

                        raw_headers = f"HTTP/{response.raw.version/10} {response.status_code}\n"
                        for key, val in response.headers.items():
                            raw_headers += f"{key}: {val}\n"
                        st.success("Network footprint successfully mapped!")
                    except requests.exceptions.RequestException as e:
                        st.error(f"Target connection failed or blocked: {str(e)}. Try switching to 'Paste Raw Logs / Headers Safely' mode.")

    else:
        st.error(
            "🛑 **ADVANCED USER MODE: OPERATIONAL SECURITY (OPSEC) WARNING**\n\n"
            "**NEVER visit a suspicious website directly in your standard browser to copy headers.** "
            "To capture logs safely, you must use a neutral, isolated intermediary tool."
        )

        with st.expander("🛠️ Step-by-Step: How to capture raw headers safely without risking your IP"):
            st.markdown(
                "If our automated scanner gets blocked by website cloaking, follow these steps to manually gather text logs safely:\n\n"
                "1. Go to a free, cloud-hosted API testing tool like **[ReqBin.com](https://reqbin.com)**.\n"
                "2. Paste the suspicious URL into ReqBin's URL bar (leave the setting on **GET**).\n"
                "3. Click **Send**.\n"
                "4. Copy that text wall from the response **Raw** tab and paste it into the box below."
            )
        
        user_logs = st.text_area("Paste raw server response logs/headers here:", height=150, placeholder="HTTP/1.1 404 Not Found\nServer: nginx...")
        manual_domain = st.text_input("Enter the domain associated with these logs (optional, for reporting):", placeholder="example.com")
        if st.button("Analyze Raw Logs Safely"):
            if not user_logs:
                st.warning("Please paste some text logs first.")
            else:
                raw_headers = user_logs
                target_domain_for_report = manual_domain

    if raw_headers:
        st.subheader("🌐 Infrastructure Insights")
        
        if redirect_chain_data:
            st.info("🔗 **Detected Redirect Chain (301/302 Hops):**")
            for hop_text in redirect_chain_data:
                st.write(hop_text)
        
        if target_domain_for_report:
            reg_date, age_days = get_domain_age(target_domain_for_report)
            if reg_date:
                if age_days < 30:
                    st.error(f"🚨 **Domain Age Alert:** Created on {reg_date} ({age_days} days ago). This is a brand-new website!")
                elif age_days < 180:
                    st.warning(f"⚠️ **Domain Age Warning:** Created on {reg_date} ({age_days} days ago). Relatively new infrastructure.")
                else:
                    st.success(f"📅 **Domain Age:** Created on {reg_date} ({age_days} days ago).")

        with st.spinner("AI Agent analyzing structural indicators..."):
            system_instruction = (
                "You are an automated Cyber Threat Intelligence Agent. Analyze the provided "
                "HTTP server response headers or text logs. Look for specific indicators of compromise: response cloaking "
                "(e.g., unexpected 404s/403s on active targets), affiliate tracking IDs (like _subid or click tokens), "
                "suspicious short-lived session cookies, and typosquatting indicators. "
                "CRITICAL FORMATTING RULE: Your first line of output MUST read exactly 'THREAT LEVEL ASSESSMENT: HIGH', "
                "'THREAT LEVEL ASSESSMENT: MEDIUM', or 'THREAT LEVEL ASSESSMENT: LOW'. Follow this with a 3-bullet point technical breakdown."
            )
            full_prompt = f"{system_instruction}\n\n[INPUT LOG DATA]:\n{raw_headers}"
            
            try:
                ai_analysis = model.generate_content(full_prompt)
                analysis_text = ai_analysis.text
                st.subheader("📊 AI Agent Security Verdict")
                st.write(analysis_text)
                
                lines = [line.strip().upper() for line in analysis_text.split('\n') if line.strip()]
                first_line = lines if lines else ""
                st.divider()

                parsed_dest = urllib.parse.urlparse(target_domain_for_report)
                clean_domain_string = parsed_dest.netloc if parsed_dest.netloc else parsed_dest.path
                if ":" in clean_domain_string:
                    clean_domain_string = clean_domain_string.split(':')[0]
                clean_domain_string = clean_domain_string.replace("www.", "")

                if "HIGH" in first_line:
                    st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds.")
                    if clean_domain_string:
                        st.markdown("### 📢 Take Action Immediately")
                        st.write("Protect the public by copying this domain and submitting it to the global blocklist:")
                        st.text_input("Click inside to copy target domain:", value=clean_domain_string)
                        google_report_url = "https://google.com"
                        st.link_button("📢 Open Google Safe Browsing Form", google_report_url, type="primary")
                elif "MEDIUM" in first_line:
                    st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                else:
                    st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")
            except Exception as gen_err:
                st.error(f"Analysis engine hit a barrier: {str(gen_err)}")
