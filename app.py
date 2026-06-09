import streamlit as st
import google.generativeai as genai
import google.ai.generativelanguage as glm
import requests
import urllib.parse
from datetime import datetime

# 1. APPLICATION BRANDING & CONTENT CONFIGURATION
st.set_page_config(page_title="🛡️ ShieldAI: Open-Source Link Investigator", layout="centered")
st.title("🛡️ ShieldAI: Autonomous Link Investigator")
st.write("Analyze a live link or safely paste raw server logs/headers to discover its true structural intent.")

# ==========================================
# ⚠️ SECURITY DISCLAIMER & SAFETY SHIELD
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
# 🤝 LAYMAN TRANSPARENCY & PRIVACY SUMMARY
# ==========================================
with st.expander("🤝 How does ShieldAI protect my privacy? (Layman's Explanation)"):
    st.markdown(
        "### We designed this tool to be completely transparent and safe for you to use:\n\n"
        "1. **Your IP Address is Invisible:** When you scan a link, our server acts as a digital shield. "
        "The suspicious website only sees our neutral cloud computing hosting network—**your personal device, home location, and real identity are never exposed** to the target.\n"
        "2. **We Don't Track You:** ShieldAI does not use tracking cookies, account logins, or user databases. "
        "Your scans are completely private and processed in real time.\n"
        "3. **Completely Open Source (Apache 2.0):** Our entire blueprint is completely public! "
        "Anyone in the world can inspect our exact code to verify that it handles data securely and contains no hidden malicious agendas.\n"
        "4. **AI-Powered Diagnostics:** We pipe the raw technical data into Google's Gemini engine to translate "
        "complex code into clear security assessments, helping you make informed safety decisions instantly."
    )

st.divider()

# 2. CYBER THREAT METRICS HOOKS (DOMAIN AGE ENGINE)
def get_domain_age(url_string):
    """Queries the open RDAP registry protocol to gather a site's precise creation date."""
    try:
        parsed_url = urllib.parse.urlparse(url_string)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if ":" in domain:
            domain = domain.split(':')
        if domain.startswith("www."):
            domain = domain[4:]
            
        rdap_url = f"https://rdap.org{domain}"
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
# 3. INTERACTION GATEWAY & API ENVIRONMENT INITIALIZATION
API_KEY = st.secrets.get("GEMINI_API_KEY")

if not API_KEY:
    st.error("Missing Gemini API Key. Please configure it in your Streamlit platform secrets.")
else:
    genai.configure(api_key=API_KEY)
    
    # Structural Variable Enforcement Type Schema Definition for Object Outputs
    response_schema = glm.Schema(
        type=glm.Type.OBJECT,
        properties={
            "threat_level": glm.Schema(type=glm.Type.STRING, description="Must be exactly: LOW, MEDIUM, or HIGH"),
            "technical_breakdown": glm.Schema(type=glm.Type.STRING, description="A detailed bulleted cyber threat intelligence analysis text report.")
        },
        required=["threat_level", "technical_breakdown"]
    )
    
    model = genai.GenerativeModel(
        'gemini-3.5-flash',
        generation_config={"response_mime_type": "application/json", "response_schema": response_schema}
    )

    analysis_mode = st.radio("Choose Investigation Method:", ("Scan a Live Link Anonymously", "Paste Raw Logs / Headers Safely"))
    raw_headers, target_domain_for_report, redirect_chain_data = None, "", []

    # ==========================================
    # INPUT MODE 1: LIVE REDIRECT INVESTIGATOR
    # ==========================================
    if analysis_mode == "Scan a Live Link Anonymously":
        user_url = st.text_input("Enter the suspicious URL to investigate:", placeholder="example.com")
        if st.button("Investigate Link Safely"):
            if not user_url:
                st.warning("Please enter a URL first.")
            else:
                target_url = user_url if user_url.startswith(('http://', 'https://')) else 'https://' + user_url
                target_domain_for_report = target_url

                with st.spinner("Analyzing network redirect chains and extracting payloads..."):
                    try:
                        headers_payload = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                        response = requests.get(target_url, headers=headers_payload, timeout=7, allow_redirects=True)
                        
                        # Accumulate untouched, unmodified tracking strings into data history
                        if response.history:
                            for idx, hop in enumerate(response.history):
                                redirect_chain_data.append(f"Hop {idx+1}: {hop.url} (Status: {hop.status_code})")
                        
                        redirect_chain_data.append(f"Final Destination: {response.url} (Status: {response.status_code})")
                        target_domain_for_report = response.url

                        raw_headers = f"HTTP/{response.raw.version/10} {response.status_code}\n" + "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                        st.success("Network footprint successfully mapped!")
                    except Exception as e:
                        st.error(f"Target connection failed or blocked: {str(e)}. Try switching to 'Paste Raw Logs' manual mode.")
    # ==========================================
    # INPUT MODE 2: MANUAL OPSEC CODE LOGGER
    # ==========================================
    else:
        st.error(
            "🛑 **ADVANCED USER MODE: OPERATIONAL SECURITY (OPSEC) WARNING**\n\n"
            "**NEVER visit a suspicious website directly in your standard browser to copy headers.** "
            "To capture logs safely without executing malware, you must use an isolated intermediary tool."
        )
        with st.expander("🛠️ Step-by-Step: How to capture raw headers safely without risking your IP"):
            st.markdown(
                "If our automated scanner gets blocked by aggressive website cloaking, capture metrics safely:\n\n"
                "1. Go to a free, cloud-hosted developer testing platform like **[ReqBin.com](https://reqbin.com)**.\n"
                "2. Paste the suspicious URL into ReqBin's URL field (leave the setting on **GET**).\n"
                "3. Click **Send**.\n"
                "4. Copy the complete text wall from the response **Raw** tab and paste it into the box below."
            )
        
        user_logs = st.text_area("Paste raw server response logs/headers here:", height=150, placeholder="HTTP/1.1 404 Not Found\nServer: nginx...")
        manual_domain = st.text_input("Enter the domain associated with these logs (optional, for tracking):", placeholder="example.com")
        if st.button("Analyze Raw Logs Safely"):
            if not user_logs:
                st.warning("Please paste some text logs first.")
            else:
                raw_headers, target_domain_for_report = user_logs, manual_domain

    # ==========================================
    # 4. CORE PIPELINE METRICS & VISUALIZATION
    # ==========================================
    if raw_headers:
        st.subheader("🌐 Infrastructure Insights")
        
        # Isolated Render Box - locks original links inside an un-clickable copy code sandbox
        if redirect_chain_data:
            st.info("🔗 **Detected Redirect Chain (301/302 Hops):**")
            st.caption("🔒 *Note: Original investigative URLs are rendered inside an isolated code block. They are completely un-clickable but remain 100% intact for technical analysis copy-pasting.*")
            full_chain_text = "\n".join(redirect_chain_data)
            st.code(full_chain_text, language="text")
            
        # Domain Registration Verification Engine
        if target_domain_for_report:
            reg_date, age_days = get_domain_age(target_domain_for_report)
            if reg_date:
                if age_days < 30:
                    st.error(f"🚨 **Domain Age Alert:** Created on {reg_date} ({age_days} days ago). This is a brand-new website!")
                elif age_days < 180:
                    st.warning(f"⚠️ **Domain Age Warning:** Created on {reg_date} ({age_days} days ago). Relatively new infrastructure.")
                else:
                    st.success(f"📅 **Domain Age:** Created on {reg_date} ({age_days} days ago).")

        # 5. CORE AI REASONING EXECUTOR
        with st.spinner("AI Agent analyzing structural indicators..."):
            try:
                system_instruction = "You are an automated Cyber Threat Intelligence Agent. Analyze the provided HTTP server response headers or text logs. Look for specific indicators of compromise: response cloaking, affiliate tracking IDs (like _subid or click tokens), suspicious short-lived session cookies, and typosquatting indicators. Populate the structural threat_level and technical_breakdown variables accurately."
                ai_analysis = model.generate_content(f"{system_instruction}\n\n[INPUT LOG DATA]:\n{raw_headers}")
                
                # Parse exact programmatic values out of the structured JSON block
                import json
                structured_data = json.loads(ai_analysis.text)
                threat_level = structured_data.get("threat_level", "MEDIUM").upper()
                breakdown_text = structured_data.get("technical_breakdown", "")

                st.subheader("📊 AI Agent Security Verdict")
                st.write(f"**Threat Level:** {threat_level}")
                st.write(breakdown_text)
                st.divider()

                # Calculate clean domain parameters for the manual clipboard reporting string
                parsed_dest = urllib.parse.urlparse(target_domain_for_report)
                clean_domain_string = parsed_dest.netloc if parsed_dest.netloc else parsed_dest.path
                if ":" in clean_domain_string:
                    clean_domain_string = clean_domain_string.split(':')
                clean_domain_string = clean_domain_string.replace("www.", "")

                # Strict conditional formatting using native variable types instead of text parsing
                if threat_level == "HIGH":
                    st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds.")
                    if clean_domain_string:
                        st.markdown("### 📢 Take Action Immediately")
                        st.write("Protect the public by copying this domain and submitting it to the global blocklist:")
                        st.text_input("Click inside to copy target domain:", value=clean_domain_string)
                        
                        # Hardcoded explicit routing path directly to Google's safe browsing infrastructure
                        st.link_button(label="📢 Open Google Safe Browsing Form", url="https://www.google.com/safebrowsing/report_phish/", type="primary")
                elif threat_level == "MEDIUM":
                    st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                else:
                    st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")
            except Exception as gen_err:
                st.error(f"Analysis engine hit a barrier: {str(gen_err)}")
