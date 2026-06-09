import streamlit as st
import google.generativeai as genai
import requests
import urllib.parse

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

st.divider() # Visual separation line

# 2. Securely Initialize Gemini API
API_KEY = st.secrets.get("GEMINI_API_KEY")

if not API_KEY:
    st.error("Missing Gemini API Key. Please configure it in your platform settings.")
else:
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel('gemini-3.5-flash')

    # 3. Choose Input Type
    analysis_mode = st.radio("Choose Investigation Method:", ("Scan a Live Link Anonymously", "Paste Raw Logs / Headers Safely"))

    raw_headers = None
    target_domain_for_report = ""

    if analysis_mode == "Scan a Live Link Anonymously":
        user_url = st.text_input("Enter the suspicious URL to investigate:", placeholder="example.com")
        if st.button("Investigate Link Safely"):
            if not user_url:
                st.warning("Please enter a URL first.")
            else:
                if not user_url.startswith(('http://', 'https://')):
                    target_url = 'http://' + user_url
                else:
                    target_url = user_url
                
                # Save clean version for the reporting link
                target_domain_for_report = target_url

                with st.spinner("Fetching technical headers anonymously..."):
                    try:
                        headers_payload = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        response = requests.head(target_url, headers=headers_payload, timeout=5, allow_redirects=True)
                        
                        raw_headers = f"HTTP/{response.raw.version/10} {response.status_code}\n"
                        for key, val in response.headers.items():
                            raw_headers += f"{key}: {val}\n"
                        st.success("Headers successfully captured from a neutral cloud node!")
                    except requests.exceptions.RequestException as e:
                        st.error(f"Target connection failed or blocked: {str(e)}. Try switching to 'Paste Raw Logs / Headers Safely' mode.")

    else:
        # ==========================================
        # 🛑 ADVANCED USER RISK WARNING & HOW-TO
        # ==========================================
        st.error(
            "🛑 **ADVANCED USER MODE: OPERATIONAL SECURITY (OPSEC) WARNING**\n\n"
            "**NEVER visit a suspicious website directly in your standard browser to copy headers.** "
            "Doing so executes the malicious scripts on your machine and exposes your real IP address to the attacker. "
            "To capture logs safely, you must use a neutral, isolated intermediary tool."
        )
        
        with st.expander("🛠️ Step-by-Step: How to capture raw headers safely without risking your IP"):
            st.markdown(
                "If our automated scanner gets blocked by website cloaking, follow these steps to manually gather text logs safely:\n\n"
                "1. Go to a free, cloud-hosted API testing tool like **[ReqBin.com](https://reqbin.com)**.\n"
                "2. Paste the suspicious URL into ReqBin's URL bar (leave the setting on **GET**).\n"
                "3. Click **Send**.\n"
                "4. ReqBin's cloud servers will visit the site *for you*, keeping your device completely safe. "
                "Once the request completes, click the **Raw** tab in the right-hand response panel.\n"
                "5. Copy that text wall and paste it into the box below."
            )
        
        user_logs = st.text_area("Paste raw server response logs/headers here:", height=200, placeholder="HTTP/1.1 404 Not Found\nServer: nginx...")
        manual_domain = st.text_input("Enter the domain associated with these logs (optional, for reporting):", placeholder="example.com")
        if st.button("Analyze Raw Logs Safely"):
            if not user_logs:
                st.warning("Please paste some text logs first.")
            else:
                raw_headers = user_logs
                target_domain_for_report = manual_domain

    # 4. Core AI Processing Engine
    if raw_headers:
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
                
                st.subheader("📊 AI Agent Security Verdict")
                st.write(ai_analysis.text)
                
                # Dynamic visual banners based on structural header verdicts
                if "THREAT LEVEL ASSESSMENT: HIGH" in ai_analysis.text.upper():
                    st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds.")
                    
                    # 5. AUTOMATED REPORT GENERATION ENGINE
                    if target_domain_for_report:
                        # Clean the URL formatting for safe transit
                        encoded_url = urllib.parse.quote(target_domain_for_report)
                        # Build the pre-filled Google Safe Browsing report endpoint URL
                        google_report_url = f"https://google.com{encoded_url}"
                        
                        st.markdown("### 📢 Take Action Immediately")
                        st.write("You can protect millions of internet users by instantly adding this domain to Google Chrome's global blocklist.")
                        
                        # Display a beautiful, actionable button linking to Google
                        st.link_button("📢 Report Domain to Google Safe Browsing", google_report_url, type="primary")
                    else:
                        st.info("ℹ️ To auto-generate a 1-click Google Report link, please make sure the domain or URL input field is filled above.")
                        
                elif "THREAT LEVEL ASSESSMENT: MEDIUM" in ai_analysis.text.upper():
                    st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                else:
                    st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")
                    
            except Exception as gen_err:
                st.error(f"Analysis engine hit a barrier: {str(gen_err)}")
