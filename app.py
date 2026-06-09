import streamlit as st
import google.generativeai as genai
import requests

# 1. Configure the Web Page Layout
st.set_page_config(page_title="🛡️ ShieldAI: Open-Source Link Investigator", layout="centered")
st.title("🛡️ ShieldAI: Autonomous Link Investigator")
st.write("Analyze a live link or safely paste raw server logs/headers to discover its true structural intent.")

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
        user_logs = st.text_area("Paste raw server response logs/headers here:", height=200, placeholder="HTTP/1.1 404 Not Found\nServer: nginx...")
        if st.button("Analyze Raw Logs Safely"):
            if not user_logs:
                st.warning("Please paste some text logs first.")
            else:
                raw_headers = user_logs

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
                    st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds. (Automated Google Safe Browsing report would trigger here).")
                elif "THREAT LEVEL ASSESSMENT: MEDIUM" in ai_analysis.text.upper():
                    st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                else:
                    st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")
                    
            except Exception as gen_err:
                st.error(f"Analysis engine hit a barrier: {str(gen_err)}")
import streamlit as st
import google.generativeai as genai
import requests

# 1. Configure the Web Page Layout
st.set_page_config(page_title="🛡️ ShieldAI: Open-Source Link Investigator", layout="centered")
st.title("🛡️ ShieldAI: Autonomous Link Investigator")
st.write("Paste any suspicious URL below to safely extract headers and analyze its true structural intent.")

# 2. Securely Initialize Gemini API
# On public platforms, your API key is hidden in the platform's Environment Variables
API_KEY = st.secrets.get("GEMINI_API_KEY")

if not API_KEY:
    st.error("Missing Gemini API Key. Please configure it in your platform settings.")
else:
    genai.configure(api_key=API_KEY)
    # Using Gemini 1.5 Flash for rapid, cost-effective security text analysis
    model = genai.GenerativeModel('gemini-3.5-flash')

    # 3. User Input Form
    user_url = st.text_input("Enter the suspicious URL to investigate:", placeholder="example.com")

    if st.button("Investigate Link Safely"):
        if not user_url:
            st.warning("Please enter a URL first.")
        else:
            # Clean up user input format
            if not user_url.startswith(('http://', 'https://')):
                target_url = 'http://' + user_url
            else:
                target_url = user_url

            with st.spinner("Fetching technical headers anonymously..."):
                try:
                    # Fetch ONLY the headers using a standard browser footprint to mask identity
                    headers_payload = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    # 5-second timeout prevents malicious targets from hanging your public app
                    response = requests.head(target_url, headers=headers_payload, timeout=5, allow_redirects=True)
                    
                    # Format the header dictionary into plain text for the LLM
                    raw_headers = f"HTTP/{response.raw.version/10} {response.status_code}\n"
                    for key, val in response.headers.items():
                        raw_headers += f"{key}: {val}\n"
                        
                    st.success("Headers successfully captured from a neutral cloud node!")
                    
                except requests.exceptions.RequestException as e:
                    st.error(f"Could not connect to target network: {str(e)}")
                    raw_headers = None

            if raw_headers:
                with st.spinner("AI Agent analyzing structural indicators..."):
                    # Define strict analytical rules for the agent
                    system_instruction = (
                        "You are an automated Cyber Threat Intelligence Agent. Analyze the following raw "
                        "HTTP server response headers. Look for specific indicators of compromise: response cloaking "
                        "(e.g., unexpected 404s/403s on active targets), affiliate tracking IDs (like _subid or click tokens), "
                        "suspicious short-lived session cookies, and typosquatting indicators. "
                        "Output a concise Threat Level Assessment (LOW, MEDIUM, HIGH) followed by a 3-bullet point technical breakdown."
                    )
                    
                    full_prompt = f"{system_instruction}\n\n[RAW HEADERS TO ANALYZE]:\n{raw_headers}"
                    
                    try:
                        ai_analysis = model.generate_content(full_prompt)
                        
                        st.subheader("📊 AI Agent Security Verdict")
                        st.write(ai_analysis.text)
                        
                        # Future automation flag - only triggers if the word "THREAT LEVEL ASSESSMENT: HIGH" is explicitly stated
                        if "THREAT LEVEL ASSESSMENT: HIGH" in ai_analysis.text.upper():
                            st.error("🚨 CRITICAL THREAT DETECTED: This signature meets high-confidence malicious thresholds. (Automated Google Safe Browsing report would trigger here).")
                        elif "THREAT LEVEL ASSESSMENT: MEDIUM" in ai_analysis.text.upper():
                            st.warning("⚠️ WARNING: This infrastructure shows suspicious indicators. Manual verification recommended.")
                        else:
                            st.success("✅ SAFE: This website matches legitimate infrastructure patterns.")

                            
                    except Exception as gen_err:
                        st.error(f"Analysis engine hit a quota or safety barrier: {str(gen_err)}")
