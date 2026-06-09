import streamlit as st
import google.generativeai as genai
import google.ai.generativelanguage as glm
import requests
import urllib.parse
from datetime import datetime

st.set_page_config(page_title="🛡️ ShieldAI: Open-Source Link Investigator", layout="centered")
st.title("🛡️ ShieldAI: Autonomous Link Investigator")
st.write("Analyze a live link or safely paste raw server logs/headers to discover its true structural intent.")

# ⚠️ SECURITY DISCLAIMER & PRIVACY PANEL
st.warning("⚠️ **IMPORTANT SECURITY NOTICE & DISCLAIMER**\n\nThis tool is designed for educational and preliminary incident response analysis only. While it uses advanced AI threat intelligence, **no automated scanner is 100% accurate.** Use of this software is entirely at your own risk.")
with st.expander("🤝 How does ShieldAI protect my privacy? (Layman's Explanation)"):
    st.markdown("### Privacy & Transparency Protections:\n\n1. **Your IP Address is Invisible:** The suspicious website only sees our neutral hosting servers—your device identity is never exposed.\n2. **No Tracking:** We do not track cookies or collect logs.\n3. **Open Source (Apache 2.0):** Our full blueprint is open for verification.")
st.divider()

def get_domain_age(url_string):
    try:
        parsed_url = urllib.parse.urlparse(url_string)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if ":" in domain: domain = domain.split(':')[0]
        if domain.startswith("www."): domain = domain[4:]
        res = requests.get(f"https://rdap.org{domain}", timeout=3)
        if res.status_code == 200:
            for event in res.json().get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date = datetime.strptime(event.get("eventDate")[:10], "%Y-%m-%d")
                    return reg_date.strftime("%B %d, %Y"), (datetime.now() - reg_date).days
    except Exception: pass
    return None, None
API_KEY = st.secrets.get("GEMINI_API_KEY")
if not API_KEY:
    st.error("Missing Gemini API Key. Please configure it in your platform settings.")
else:
    genai.configure(api_key=API_KEY)
    
    # Establish a fixed variable schema data-type constraint for Gemini
    response_schema = glm.Schema(
        type=glm.Type.OBJECT,
        properties={
            "threat_level": glm.Schema(type=glm.Type.STRING, description="Must be exactly: LOW, MEDIUM, or HIGH"),
            "technical_breakdown": glm.Schema(type=glm.Type.STRING, description="A bulleted security threat analysis summary text box.")
        },
        required=["threat_level", "technical_breakdown"]
    )
    
    model = genai.GenerativeModel(
        'gemini-3.5-flash',
        generation_config={"response_mime_type": "application/json", "response_schema": response_schema}
    )

    analysis_mode = st.radio("Choose Investigation Method:", ("Scan a Live Link Anonymously", "Paste Raw Logs / Headers Safely"))
    raw_headers, target_domain_for_report, redirect_chain_data = None, "", []

    if analysis_mode == "Scan a Live Link Anonymously":
        user_url = st.text_input("Enter the suspicious URL to investigate:", placeholder="example.com")
        if st.button("Investigate Link Safely"):
            if not user_url: st.warning("Please enter a URL first.")
            else:
                target_url = user_url if user_url.startswith(('http://', 'https://')) else 'https://' + user_url
                target_domain_for_report = target_url
                with st.spinner("Analyzing network redirect chains..."):
                    try:
                        res = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=7, allow_redirects=True)
                        if res.history:
                            for idx, hop in enumerate(res.history): 
                                redirect_chain_data.append(f"Hop {idx+1}: {hop.url} (Status: {hop.status_code})")
                        redirect_chain_data.append(f"Final Destination: {res.url} (Status: {res.status_code})")
                        target_domain_for_report = res.url
                        raw_headers = f"HTTP/{res.raw.version/10} {res.status_code}\n" + "\n".join([f"{k}: {v}" for k, v in res.headers.items()])
                        st.success("Network footprint mapped!")
                    except Exception as e: st.error(f"Scanner blocked: {str(e)}. Try switching to Manual Logs mode.")
    else:
        st.error("🛑 **OPSEC WARNING:** NEVER visit a suspicious site directly in your normal browser to grab logs.")
        with st.expander("🛠️ Step-by-Step: How to capture raw headers safely"):
            st.markdown("1. Go to **[ReqBin.com](https://reqbin.com)**.\n2. Paste the URL and click **Send**.\n3. Copy the text from the response **Raw** tab.")
        user_logs = st.text_area("Paste raw server response logs/headers here:", height=150)
        manual_domain = st.text_input("Enter the domain associated with these logs (optional):")
        if st.button("Analyze Raw Logs Safely"):
            if not user_logs: st.warning("Please paste logs first.")
            else: raw_headers, target_domain_for_report = user_logs, manual_domain
    if raw_headers:
        st.subheader("🌐 Infrastructure Insights")
        
        # Safe Literal Render Sandbox - completely eliminates active links
        if redirect_chain_data:
            st.info("🔗 **Detected Redirect Chain (301/302 Hops):**")
            st.caption("🔒 *Note: Original URLs are rendered inside an isolated code sandbox. They are completely un-clickable but remain 100% intact for technical copy-pasting.*")
            full_chain_text = "\n".join(redirect_chain_data)
            st.code(full_chain_text, language="text")
            
        if target_domain_for_report:
            reg_date, age_days = get_domain_age(target_domain_for_report)
            if reg_date:
                if age_days < 30: st.error(f"🚨 **Domain Age Alert:** Created on {reg_date} ({age_days} days ago). Brand-new site!")
                elif age_days < 180: st.warning(f"⚠️ **Domain Age Warning:** Created on {reg_date} ({age_days} days ago).")
                else: st.success(f"📅 **Domain Age:** Created on {reg_date} ({age_days} days ago).")

        with st.spinner("AI Agent analyzing structural indicators..."):
            try:
                system_instruction = "You are an automated Cyber Threat Intelligence Agent. Analyze the provided HTTP server response headers or text logs. Look for specific indicators of compromise: response cloaking, affiliate tracking IDs (like _subid or click tokens), suspicious short-lived session cookies, and typosquatting indicators. Populate the structural threat_level and technical_breakdown variables accurately."
                ai_analysis = model.generate_content(f"{system_instruction}\n\n[INPUT LOG DATA]:\n{raw_headers}")
                
                import json
                structured_data = json.loads(ai_analysis.text)
                threat_level = structured_data.get("threat_level", "MEDIUM").upper()
                breakdown_text = structured_data.get("technical_breakdown", "")

                st.subheader("📊 AI Agent Security Verdict")
                st.write(f"**Threat Level:** {threat_level}")
                st.write(breakdown_text)
                st.divider()

                parsed_dest = urllib.parse.urlparse(target_domain_for_report)
                clean_domain_string = parsed_dest.netloc if parsed_dest.netloc else parsed_dest.path
                if ":" in clean_domain_string: clean_domain_string = clean_domain_string.split(':')[0]
                clean_domain_string = clean_domain_string.replace("www.", "")

                # Strict variable object matching
                if threat_level == "HIGH":
                    st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds.")
                    if clean_domain_string:
                        st.markdown("### 📢 Take Action Immediately")
                        st.text_input("Click inside to copy target domain:", value=clean_domain_string)
                        st.link_button("📢 Open Google Safe Browsing Form", "https://google.com", type="primary")
                elif threat_level == "MEDIUM":
                    st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                else:
                    st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")
            except Exception as gen_err: st.error(f"Analysis engine hit a barrier: {str(gen_err)}")
