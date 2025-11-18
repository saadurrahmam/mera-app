
# streamlit_app.py - V14: Fully Responsive (Final Upgrade)

import asyncio
import json
import sqlite3
import pandas as pd 
from datetime import datetime
from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode
import altair as alt 
import time 
import io 
import random 

import aiohttp
import streamlit as st
from bs4 import BeautifulSoup

# ==================================
# DEBUG MODE FOR CHARTS (SET TO TRUE FOR DEMO WITH ALL SEVERITIES)
# ==================================
DEBUG_MODE_CHARTS = False 

# ==================================
# CUSTOM CSS FOR DARK MODE PROFESSIONAL LOOK & RESPONSIVENESS
# ==================================
st.markdown("""
<style>
/* --- UNIFIED DARK MODE COLOR PALETTE --- */
:root {
    --primary-color: #00796b; /* Deep Teal (for general accents) */
    --accent-color: #d32f2f; /* Darker Red (for progress bar/critical action) */
    --background-dark: #1e1e1e; /* Dark background */
    --background-card: #2d2d2d; /* Card background (slightly lighter than app background) */
    --text-white: #f5f5f5; /* Light text */
    --text-light-gray: #b0b0b0; /* Subtext */
    --critical-red: #f44336; /* Bright Red for Critical findings */
    --high-orange: #ff9800; /* Orange for High findings */
    --medium-teal: #00bcd4; /* Brighter Teal for Medium findings */
    --low-blue: #2196f3; /* Blue for Low findings */
    --soft-gray-blue: #3a3a3a; /* Darker background for guidance box */
}

/* --- BASE & UTILITIES (Applying Dark Mode Background) --- */
.stApp {
    background-color: var(--background-dark); 
    color: var(--text-white);
}
.main {
    color: var(--text-white);
}

/* --- 1. HEADERS & TYPOGRAPHY --- */
.st-emotion-cache-183v29e > h1, .st-emotion-cache-1l00psu > h1 { 
    color: var(--text-white) !important; 
    font-weight: 900;
    letter-spacing: -1.2px; 
    border-bottom: 3px solid #3a3a3a; 
    padding-bottom: 15px; 
    margin-bottom: 30px; 
}
.scanner-heading-no-border h1 {
    border-bottom: none !important; 
}
h3 {
    border-left: 6px solid var(--primary-color); 
    padding-left: 18px;
    margin-top: 3.5rem; 
    margin-bottom: 1.5rem;
    font-size: 1.8rem;
    color: var(--text-white);
    font-weight: 700;
}

/* --- 2. CARD/BOX STYLING (Dashboard/History Background Refinement) --- */
.st-emotion-cache-1r6r000, .st-emotion-cache-1n103ah, .st-emotion-cache-1gsv2z1, .st-emotion-cache-1kywczu, .st-emotion-cache-1vb648g { 
    background-color: rgba(45, 45, 45, 0.85);
    box-shadow: 0 6px 12px rgba(0, 0, 0, 0.6);
    border-radius: 12px; 
    padding: 30px; 
    margin-bottom: 30px; 
    border: 1px solid #4a4a4a;
}
/* Reduce padding on very small screens for better use of space */
@media (max-width: 600px) {
    .st-emotion-cache-1r6r000, .st-emotion-cache-1n103ah, .st-emotion-cache-1gsv2z1, .st-emotion-cache-1kywczu, .st-emotion-cache-1vb648g {
        padding: 15px; /* Half the padding for mobile */
    }
}

/* --- 3. METRIC BOXES (KPIs) --- */
.metric-box {
    background: linear-gradient(135deg, #004d40 0%, #00796b 100%); 
    padding: 20px 25px;
    border-radius: 12px;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
    height: 100%;
}
/* Ensure Metrics stack nicely on small screens */
@media (max-width: 600px) {
    .metric-box {
        margin-bottom: 15px; /* Add space between stacked boxes */
    }
    /* Streamlit columns for metrics on mobile */
    .st-emotion-cache-13lrm7f { /* This targets the outer div wrapping the columns in Streamlit */
        flex-direction: column !important; /* Force columns to stack */
    }
}

/* --- 4. SCANNER STATUS BAR --- */
div[data-testid="stStatusWidget"] {
    background-color: var(--accent-color) !important; 
    border-radius: 10px !important; 
    margin-bottom: 10px !important;
    color: var(--text-white) !important;
    border: none !important;
    padding: 10px 15px !important;
}
.stSuccess {
    background-color: var(--accent-color) !important;
    border-radius: 10px !important;
    color: var(--text-white) !important;
    border: none !important;
}

/* --- 5. PROGRESS BAR --- */
.stProgress {
    margin-bottom: 20px;
}
.stProgress > div > div {
    background-color: #3a3a3a;
    border-radius: 10px;
}
.stProgress > div > div > div {
    background-color: var(--accent-color);
    border-radius: 10px;
    color: var(--text-white);
}

/* --- 6. TERMINAL LOG SPACING --- */
.log-entry-container {
    background-color: #1c2833;
    border-radius: 10px;
    padding: 10px 15px;
    margin-bottom: 8px;
    border: 1px solid #4a4a4a;
    /* Allow scrolling for long log lines on small screens */
    overflow-x: auto; 
}
.log-entry-container pre {
    color: #2ecc71; 
    font-family: 'Consolas', 'Monaco', monospace; 
    font-size: 0.9rem;
    margin: 0;
    padding: 0;
}

/* --- 7. GUIDANCE BOX (Darker Subtle Background) --- */
.guidance-box {
    background-color: var(--soft-gray-blue); 
    padding: 18px 25px; 
    border-radius: 10px;
    border-left: 5px solid var(--primary-color); 
    color: var(--text-white); 
    margin-bottom: 25px; 
}

/* --- 8. CHART RESPONSIVENESS FIX (Crucial for Pie Chart on mobile) --- */
/* Targetting Altair charts to ensure they scale down */
@media (max-width: 600px) {
    div[data-testid="stDeck"] > div {
        flex-direction: column !important; /* Stack columns */
    }
    /* Pie Chart Container Fix (Streamlit default size) */
    div[data-testid="stPlotlyChart"] {
         width: 100% !important; 
    }
}

/* --- 9. Dataframe Horizontal Scroll on Mobile --- */
/* Ensure dataframes don't overflow the screen */
div[data-testid="stDataFrame"] {
    overflow-x: auto;
}
</style>
""", unsafe_allow_html=True)
# ==================================
# DATABASE SETUP 
# ==================================
conn = sqlite3.connect('scan_history.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
conn.commit()

c.execute("SELECT * FROM users WHERE username='admin'")
if not c.fetchone():
    c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
    conn.commit()

# ==================================
# CONFIG
# ==================================
USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
XSS_MARKER = "INJECT_XSS_TEST_12345"
SQLI_MARKER_SIMPLE = "'"
SQLI_TIME_PAYLOAD = "' OR (SELECT 20 FROM (SELECT(SLEEP(4))))--" 
DELAY_THRESHOLD = 3.5 

FILE_INCLUSION_PAYLOADS = [
    "../../../../etc/passwd",
    "file:///etc/passwd",
    "http://127.0.0.1/nonexistent.txt" 
]
FILE_INCLUSION_INDICATORS = [
    "root:x", 
    "failed opening required",
    "No such file or directory"
]

XSS_PAYLOADS = [
    XSS_MARKER,
    f"<{XSS_MARKER}>",
    f"javascript:alert('{XSS_MARKER}')"
]
SQL_ERROR_INDICATORS = [
    "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
    "unclosed quotation mark", "odbc", "native client",
    "pq: syntax error", "you have an error in your sql",
]
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security", 
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Permissions-Policy" 
]

# ==================================
# CRAWLER & PROBER CLASSES
# ==================================
class Crawler:
    def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout_total = timeout
        self.timeout = aiohttp.ClientTimeout(total=timeout) 
        self.seen = set()
        self.forms = []
        self.pages = []
        self.logger = logger or (lambda *a, **k: None)
        self.headers_info = {} 

    def same_host(self, url):
        p = urlparse(url)
        return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

    def normalize(self, base, link):
        joined = urljoin(base, link)
        clean, _ = urldefrag(joined)
        return clean

    def parse_forms(self, base_url, html):
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                typ = inp.get("type") or inp.name
                inputs.append({"name": name, "type": typ})
            forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
        return forms

    async def fetch(self, session, url):
        start_time = time.time()
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                text = await resp.text(errors="ignore")
                elapsed = time.time() - start_time
                return resp.status, text, elapsed, resp.headers
        except Exception as e:
            self.logger(f"fetch error: {url} -> {type(e).__name__}: {e}")
            return None, None, None, None

    async def crawl(self):
        from asyncio import Queue
        q = Queue()
        await q.put((self.base_url, 0))
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}) as session:
            while not q.empty() and len(self.seen) < self.max_pages:
                url, depth = await q.get()
                url_clean = url.split('#')[0] 
                if url_clean in self.seen or depth > self.max_depth:
                    continue
                
                status, text, elapsed_time, headers = await self.fetch(session, url_clean) 
                
                self.seen.add(url_clean)

                if url_clean == self.base_url:
                    self.headers_info = {k:v for k,v in headers.items()} 

                if text is None or elapsed_time is None:
                    continue
                
                self.pages.append({"url": url_clean, "status": status, "body": text, "baseline_time": elapsed_time})
                forms = self.parse_forms(url_clean, text)
                for f in forms:
                    f["action"] = self.normalize(url_clean, f["action"])
                    self.forms.append(f)
                if depth < self.max_depth:
                    soup = BeautifulSoup(text, "lxml")
                    for a in soup.find_all("a", href=True):
                        link = self.normalize(url_clean, a["href"])
                        if self.same_host(link) and link not in self.seen:
                            await q.put((link, depth + 1))
        return {"pages": self.pages, "forms": self.forms, "headers": self.headers_info}

class Prober:
    def __init__(self, concurrency=8, timeout=20, logger=None):
        self.concurrency = concurrency
        self.timeout_total = timeout 
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.findings = []
        self.logger = logger or (lambda *a, **k: None)

    async def fetch_probe(self, session, method, url, data=None):
        start_time = time.time()
        try:
            if method == 'get':
                async with session.get(url, params=data, timeout=self.timeout) as resp:
                    text = await resp.text(errors="ignore")
            else:
                async with session.post(url, data=data, timeout=self.timeout) as resp:
                    text = await resp.text(errors="ignore")
            elapsed = time.time() - start_time
            return text, elapsed
        except Exception as e:
            self.logger(f"Probe error: {url} -> {type(e).__name__}: {e}")
            return "", None

    def check_security_headers(self, headers):
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for required_header in REQUIRED_SECURITY_HEADERS:
            if required_header.lower() not in headers_lower:
                self.findings.append({
                    "type": "Missing HTTP Security Header",
                    "severity": "Low", 
                    "vector": "Response Headers",
                    "url": "Base URL",
                    "param": required_header,
                    "evidence": f"The response is missing the critical '{required_header}' header."
                })
        
        if headers_lower.get('x-content-type-options', '').lower() != 'nosniff':
             self.findings.append({
                 "type": "Security Misconfiguration",
                 "severity": "Low", 
                 "vector": "Response Headers",
                 "url": "Base URL",
                 "param": "X-Content-Type-Options: nosniff",
                 "evidence": "X-Content-Type-Options header is missing or not set to 'nosniff'."
             })


    async def test_url_param_reflection(self, session, page_data):
        url = page_data["url"]
        baseline_time = page_data["baseline_time"] if page_data["baseline_time"] is not None else self.timeout_total 
        
        parts = list(urlsplit(url))
        query_string = parts[3]
        if not query_string:
            return
            
        query = parse_qs(query_string, keep_blank_values=True)
        
        for param in list(query.keys()):
            orig_values = query[param]
            
            # 1. XSS Reflection Tests
            for payload in XSS_PAYLOADS:
                query[param] = [payload]
                parts[3] = urlencode(query, doseq=True)
                test_url = urlunsplit(parts)
                text_xss, _ = await self.fetch_probe(session, 'get', test_url)
                
                if XSS_MARKER in text_xss: 
                    self.findings.append({"type": "Reflected XSS (XSS)", "severity": "High", "vector": "URL Query Parameter", "url": test_url, "param": param, "evidence": f"Injected payload reflected in response (e.g., '{payload[:20]}...')" })
                    break 
            
            # 2. SQLI Error-Based Test
            query[param] = [SQLI_MARKER_SIMPLE]
            parts[3] = urlencode(query, doseq=True)
            test_url_sqli_err = urlunsplit(parts)
            stext_err, _ = await self.fetch_probe(session, 'get', test_url_sqli_err)
            
            if any(ind in stext_err.lower() for ind in SQL_ERROR_INDICATORS):
                self.findings.append({"type": "SQL Injection (Error-Based)", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_sqli_err, "param": param, "evidence": "SQL error indicator present in response after single quote injection" })
            
            # 3. SQLI Time-Based (Blind) Test
            query[param] = [SQLI_TIME_PAYLOAD]
            parts[3] = urlencode(query, doseq=True)
            test_url_sqli_time = urlunsplit(parts)
            _, elapsed_time_test = await self.fetch_probe(session, 'get', test_url_sqli_time)

            if elapsed_time_test is not None and elapsed_time_test > (baseline_time + DELAY_THRESHOLD):
                 self.findings.append({"type": "Blind SQL Injection (Time-Based)", "severity": "High", "vector": "URL Query Parameter", "url": test_url_sqli_time, "param": param, "evidence": f"Response delayed by ~{elapsed_time_test:.2f}s (Baseline: {baseline_time:.2f}s). Potential blind SQLi." })
            
            # 4. IDOR/Directory Traversal/RFI (New Basic Check)
            if query[param] and query[param][0].isdigit():
                try:
                    test_id = str(int(query[param][0]) - 1)
                    query[param] = [test_id]
                    parts[3] = urlencode(query, doseq=True)
                    test_url_idor = urlunsplit(parts)
                    
                    self.findings.append({"type": "Potential Insecure Direct Object Reference (IDOR)", "severity": "Medium", "vector": "URL Query Parameter", "url": test_url_idor, "param": param, "evidence": f"Parameter looks like an ID. Accessing '{test_id}' might expose other users' data (requires manual verification)." })
                except ValueError:
                    pass

            for file_payload in FILE_INCLUSION_PAYLOADS:
                query[param] = [file_payload]
                parts[3] = urlencode(query, doseq=True)
                test_url_file = urlunsplit(parts)
                stext_file, _ = await self.fetch_probe(session, 'get', test_url_file)
                
                if any(ind in stext_file for ind in FILE_INCLUSION_INDICATORS):
                    self.findings.append({"type": "Remote File Inclusion / Directory Traversal", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_file, "param": param, "evidence": f"File access pattern (e.g., path traversal or expected file content) detected in response." })
                    break

            # Restore original values
            query[param] = orig_values

    async def run(self, pages, forms, headers):
        self.check_security_headers(headers)
        
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            tasks = []
            for p in pages:
                async def task_url(page_data=p):
                    async with sem:
                        await self.test_url_param_reflection(session, page_data)
                tasks.append(asyncio.create_task(task_url()))
            # Form testing tasks would go here
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True) 
        return self.findings

def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
    findings = []
    pages = []
    forms = []
    headers = {}
    
    async def inner():
        nonlocal findings, pages, forms, headers 
        def logger(msg): ui_log(msg)
        crawler = Crawler(target, max_pages, max_depth, timeout, logger)
        ui_log("Starting crawl and establishing baselines...")
        c_result = await crawler.crawl()
        
        pages = c_result["pages"]
        forms = c_result["forms"]
        headers = c_result["headers"]
        
        ui_log(f"Crawl finished. Found {len(pages)} pages and {len(forms)} forms.")
        prober = Prober(concurrency, timeout, logger)
        ui_log("Starting advanced vulnerability probing...")
        findings = await prober.run(pages, forms, headers) 
        ui_log("Probing finished.")
        return findings, pages, forms, headers
        
    try:
        return asyncio.run(inner())
    except Exception as e:
        ui_log(f"CRITICAL ERROR: Scan aborted: {type(e).__name__} - {e}")
        # Return initialized variables even on error
        return findings, pages, forms, headers 

def to_excel_report(target_url, findings):
    """Generates an Excel file (in bytes) from findings."""
    
    if findings:
        findings_df = pd.DataFrame(findings)
        findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
        findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
    else:
        findings_df = pd.DataFrame({'Message': ['No vulnerabilities found in this scan.']})
    
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    
    findings_df.to_excel(writer, sheet_name='Vulnerability Findings', index=False)
    
    metadata_df = pd.DataFrame({
        'Key': ['Target URL', 'Scan Date', 'Total Findings'],
        'Value': [target_url, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), len(findings)]
    })
    metadata_df.to_excel(writer, sheet_name='Metadata', index=False)
    
    # Close the writer correctly
    writer.close() 
    output.seek(0)
    return output.read()


# ==================================
# STREAMLIT UI 
# ==================================
st.set_page_config(page_title="Pro Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = ''

st.sidebar.title("🛡️ SafeScanner Pro") 
st.sidebar.markdown(f'<style>div[data-testid="stSidebar"] {{background-color: #2d2d2d;}}</style>', unsafe_allow_html=True) # Sidebar Background Color

if not st.session_state.logged_in:
    st.sidebar.header("👤 User Login")
    username = st.sidebar.text_input("Username", key="login_user")
    password = st.sidebar.text_input("Password", type="password", key="login_pass")
    login_btn = st.sidebar.button("🔑 Login", type="primary", use_container_width=True)
    
    if login_btn:
        c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
        res = c.fetchone()
        if res:
            st.session_state.logged_in = True
            st.session_state.role = res[0]
            st.sidebar.success(f"✅ Logged in as **{st.session_state.role}**")
            st.rerun()
        else:
            st.sidebar.error("❌ Invalid credentials")
else:
    page = st.sidebar.radio("Go to:", ["🏠 Dashboard","🔬 Scanner","📜 History"])
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Welcome, **{st.session_state.role}**")
    logout_btn = st.sidebar.button("🚪 Logout", type="secondary", use_container_width=True)
    if logout_btn:
        st.session_state.logged_in = False
        st.session_state.role = ''
        st.info("👋 Logged out successfully.")
        st.experimental_rerun()

    if page=="🏠 Dashboard":
        st.title("📊 Security Scan Dashboard")
        st.markdown("---")
        
        c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
        rows = c.fetchall()
        
        total_scans = len(rows)
        total_findings = 0
        finding_counts = {}
        
        # V13 FIX: Initialize all severity counts to ensure they show up as 0 if not found
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'N/A': 0,
            'Unknown': 0
        }
        
        all_findings_list = [] 
        
        # --- Actual scan data processing (Used when DEBUG_MODE_CHARTS is False) ---
        for r in rows:
            try:
                findings = json.loads(r[3]) 
                # Aggregate total findings
                total_findings += len(findings)
                
                for f in findings:
                    v_type = f.get('type', 'Unknown')
                    v_severity = f.get('severity', 'N/A')
                    
                    # Update counts based on findings
                    if v_severity in severity_counts:
                         severity_counts[v_severity] += 1
                    else:
                         severity_counts[v_severity] = 1 # Handle genuinely unexpected severity
                         
                    finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
                    all_findings_list.append({'Type': v_type, 'Severity': v_severity, 'Count': 1})
            except Exception:
                pass
        
        # --- 1. KEY METRICS (Custom Card Structure) ---
        st.subheader("💡 Key Performance Indicators")
        col1, col2, col3, col4 = st.columns(4)
        
        latest_target = rows[0][1] if rows else "N/A" 
        latest_date = rows[0][2].split(' ')[0] if rows else "N/A" 
        critical_count = severity_counts.get('Critical', 0)

        col1.markdown(f"""
        <div class="metric-box">
            <label>Total Scans 🔎</label>
            <p>{total_scans}</p>
        </div>
        """, unsafe_allow_html=True)

        col2.markdown(f"""
        <div class="metric-box">
            <label>Total Findings 🚩</label>
            <p>{total_findings}</p>
        </div>
        """, unsafe_allow_html=True)

        col3.markdown(f"""
        <div class="metric-box">
            <label>Critical Findings 🚨</label>
            <p>{critical_count}</p>
        </div>
        """, unsafe_allow_html=True)

        col4.markdown(f"""
        <div class="metric-box">
            <label>Latest Scan 📅</label>
            <p style='font-size: 1.5rem;'>{latest_date}</p>
            <p style='font-size: 0.9rem; margin-top: 5px;'>{latest_target[:30]}...</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br><br>", unsafe_allow_html=True)
        
        if total_findings > 0 or total_scans > 0: # Show charts if any scan was run
            
            # --- 2. CHART ROW 1: SEVERITY (PIE CHART) & TOP TYPES (STACKED BAR CHART) ---
            # V14 FIX: Streamlit columns will auto-stack on small screens due to CSS
            col_chart_1, col_chart_2 = st.columns(2)

            # Setup Chart Theme for Dark Mode and Transparency
            chart_theme = {
                "config": {
                    "view": {"stroke": "transparent", "fill": "transparent"}, 
                    "axis": {"domainColor": "#4a4a4a", "gridColor": "#3a3a3a", "tickColor": "#4a4a4a", "labelColor": "var(--text-light-gray)", "titleColor": "var(--text-white)"},
                    "legend": {"labelColor": "var(--text-light-gray)", "titleColor": "var(--text-white)"},
                    "title": {"color": "var(--text-white)"}
                }
            }
            alt.themes.register("custom_dark_transparent", lambda: chart_theme)
            alt.themes.enable("custom_dark_transparent")


            with col_chart_1:
                st.subheader("⚠️ Risk Severity Distribution")
                
                # Use the initialized severity_counts
                df_severity = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
                
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'N/A', 'Unknown']
                
                # Merge with baseline to ensure all categories are present (even if count is 0)
                base_df = pd.DataFrame({'Severity': severity_order})
                df_severity = pd.merge(base_df, df_severity, on='Severity', how='left').fillna(0)
                df_severity['Count'] = df_severity['Count'].astype(int)

                # Dark Mode Color Palette
                severity_colors = {
                    'Critical': '#f44336', 
                    'High': '#ff9800', 
                    'Medium': '#00bcd4', 
                    'Low': '#2196f3', 
                    'N/A': '#757575', 
                    'Unknown': '#424242'
                }

                # PIE CHART (Full Pie Chart, not donut)
                base = alt.Chart(df_severity).encode(
                    theta=alt.Theta("Count", stack=True)
                )

                pie = base.mark_arc(outerRadius=120, stroke="#1e1e1e", strokeWidth=2).encode( 
                    color=alt.Color("Severity", scale=alt.Scale(domain=severity_order, range=[severity_colors[s] for s in severity_order])),
                    order=alt.Order("Count", sort="descending"),
                    tooltip=["Severity", "Count", alt.Tooltip("Count", format=",", title="Total")] 
                )

                # Text labels for value display - set to white for dark mode
                text = base.mark_text(radius=140).encode(
                    text=alt.Text("Count", format=","),
                    order=alt.Order("Count", sort="descending"),
                    color=alt.value("white") 
                )
                
                # V14 FIX: Adjust height for better mobile viewing
                chart = (pie + text).properties(height=300, title="Severity Risk Breakdown")
                
                st.altair_chart(chart, use_container_width=True)

            with col_chart_2:
                st.subheader("🎯 Top 5 Vulnerability Types by Severity")
                
                df_top_types = pd.DataFrame(all_findings_list)
                
                # Calculate top 5 types globally across all severities
                top_types_list = df_top_types['Type'].value_counts().nlargest(5).index.tolist()
                df_top_types_filtered = df_top_types[df_top_types['Type'].isin(top_types_list)]

                # Group by type and severity to create the stacked bar data
                df_stacked_bar = df_top_types_filtered.groupby(['Type', 'Severity']).size().reset_index(name='Count')
                
                # Define stacked bar chart
                stacked_chart = alt.Chart(df_stacked_bar).mark_bar().encode(
                    x=alt.X('Count', title='Total Findings Count'),
                    y=alt.Y('Type', sort=alt.EncodingSortField(field='Count', op='sum', order='descending'), title='Vulnerability Type'),
                    color=alt.Color("Severity", scale=alt.Scale(domain=severity_order, range=[severity_colors[s] for s in severity_order])),
                    order=alt.Order("Severity", sort="descending"),
                    tooltip=['Type', 'Severity', 'Count']
                ).properties(height=300, title="Severity Breakdown by Top Types")
                
                # Add text labels (values) - set to white for dark mode
                text_layer = stacked_chart.mark_text(
                    align='left',
                    baseline='middle',
                    dx=3
                ).encode(
                    text=alt.Text('Count', format=","),
                    color=alt.value('white') 
                )
                
                st.altair_chart(stacked_chart, use_container_width=True)
                
            st.markdown("---")
            
            # --- 3. TIME SERIES TREND (Dark Mode Look) ---
            st.subheader("⏳ Scan Activity Over Time")
            
            date_findings = {}
            
            # Use original rows for time series
            rows_for_trend = c.execute("SELECT date, findings FROM scans ORDER BY date ASC").fetchall()

            for r in rows_for_trend:
                date_key = datetime.strptime(r[0].split(' ')[0], '%Y-%m-%d').date()
                try:
                    num_findings = len(json.loads(r[1]))
                    date_findings[date_key] = date_findings.get(date_key, 0) + num_findings
                except:
                     pass

            df_trend = pd.DataFrame(list(date_findings.items()), columns=['Date', 'Findings Count']).sort_values('Date')
            
            # Use darker colors for area chart in dark mode
            line_chart = alt.Chart(df_trend).mark_area(
                line={'color':'#00a18c'}, 
                color=alt.Gradient(
                    gradient='linear',
                    stops=[alt.GradientStop(color='#2d2d2d', offset=0), alt.GradientStop(color='rgba(0, 121, 107, 0.4)', offset=1)], 
                    x1=1,
                    y1=1,
                    x2=1,
                    y2=0
                ),
                interpolate='monotone',
                opacity=0.9
            ).encode(
                x=alt.X('Date:T', title='Scan Date'),
                y=alt.Y('Findings Count:Q', title='Total Vulnerabilities'),
                tooltip=['Date:T', 'Findings Count:Q']
            ).properties(
                title='Vulnerability Detection Trend'
            ).interactive() 
            
            st.altair_chart(line_chart, use_container_width=True)

            # --- 4. DATA TABLE (Styled for Severity visibility) ---
            st.subheader("📜 Latest Findings Overview")
            
            # Use real aggregated findings from all history 
            findings_all_latest = []
            for r in rows:
                 try:
                    findings_all_latest.extend(json.loads(r[3]))
                 except Exception:
                    pass
            
            if findings_all_latest:
                latest_findings_df = pd.DataFrame(findings_all_latest)
                latest_findings_df = latest_findings_df[['type', 'severity', 'url', 'param']].head(10)
                latest_findings_df.columns = ['Type', 'Severity', 'Affected URL', 'Parameter']
                
                # Apply severity text color styling for best readability in dark mode
                def color_severity_text_dark(val):
                    if val == 'Critical': return 'color: #f44336; font-weight: bold;' 
                    if val == 'High': return 'color: #ff9800; font-weight: bold;'
                    if val == 'Medium': return 'color: #00bcd4; font-weight: bold;'
                    if val == 'Low': return 'color: #2196f3;'
                    return 'color: #f5f5f5;' # White text for general info

                styled_df = latest_findings_df.style.applymap(color_severity_text_dark, subset=['Severity'])
                
                st.dataframe(styled_df, use_container_width=True, hide_index=True)
                st.caption(f"Showing 10 most recent findings from a total of {total_findings} aggregated findings. Severity colors indicate risk.")


        else:
            st.info("ℹ️ No scan findings available to display charts. Please run a scan first!")

    elif page=="🔬 Scanner":
        # APPLY CLASS TO REMOVE BORDER-BOTTOM
        st.markdown('<div class="scanner-heading-no-border">', unsafe_allow_html=True)
        st.title("🔬 Web Vulnerability Scan")
        st.markdown('</div>', unsafe_allow_html=True)
        
        # IMPROVED GUIDANCE BOX (Darker background)
        st.markdown("""
        <div class="guidance-box">
        💡 <strong>Expert Guidance:</strong> Use a fully qualified URL (http/https) for accurate results. For testing, use platforms like DVWA or bWAPP.
        </div>
        """, unsafe_allow_html=True)
        
        with st.expander("⚙️ Scan Configuration Parameters", expanded=True):
            target_input = st.text_input("🌐 Target URL (e.g., http://testphp.vulnweb.com)", "http://localhost:3000", key="target_url")
            
            # V14 FIX: Streamlit automatically handles stacking these columns on small screens
            col_a, col_b, col_c, col_d = st.columns(4)
            max_pages = col_a.number_input("Max Pages", 1, 1000, 100, key="max_pages", help="Max number of pages to crawl.")
            max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth", help="Max link depth to follow from the root URL.")
            concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency", help="Number of simultaneous requests to make.")
            timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout", help="Timeout for each individual request.")

            run_button = st.button("🚀 Start Advanced Scan", type="primary", use_container_width=True)
            
        # --- ENHANCED STATUS AND PROGRESS AREA ---
        status_area = st.empty()
        progress_bar = st.empty() 
        
        results_area = st.container()
        
        st.subheader("Terminal Log Output 📝")
        log_area = st.container(border=True) 

        # --- LOGIC FOR PROGRESS BAR AND LOGGING ---
        LOG_LINES = []
        def ui_log_append(msg):
            global LOG_LINES
            
            if not msg.strip():
                 return
                 
            LOG_LINES.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            
            progress_val = 0
            progress_text = ""
            
            if "Starting crawl" in msg:
                progress_val = 10
                progress_text = "10% - Starting Crawl..."
            elif "Crawl finished" in msg:
                 progress_val = 50
                 progress_text = "50% - Crawl Finished. Starting Probing..."
            elif "Probing finished" in msg:
                progress_val = 95
                progress_text = "95% - Finalizing Report..."
            
            if progress_val > 0:
                 progress_bar.progress(progress_val, text=progress_text)


            with log_area:
                 log_area.empty() 
                 log_html = ""
                 # Show last 15 lines for performance
                 for line in LOG_LINES[-15:]: 
                     # Applying the custom class for proper margin-bottom, keeping the log content clean
                     log_html += f'<div class="log-entry-container"><pre>{line}</pre></div>'
                 log_area.markdown(log_html, unsafe_allow_html=True)
                 
                 time.sleep(0.01)

        # --- SCAN EXECUTION ---
        if run_button:
            if not target_input.strip() or not target_input.startswith(('http://', 'https://')):
                status_area.error("❌ Please provide a valid URL starting with `http://` or `https://`.")
            else:
                LOG_LINES=[]
                progress_bar.progress(5, text="5% - Initializing Scanner...")
                with status_area:
                    st.info(f"🔍 Scan in progress on **{target_input}**...")
                
                progress_bar.progress(5, text="5% - Initializing Scanner...")

                log_area.empty()
                findings, pages, forms, headers = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)

                c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
                conn.commit()
                
                # Final Status/Progress Update
                progress_bar.progress(100, text="100% - Done!")
                status_area.success("✅ Scan completed successfully! Results displayed below.")
                
                with results_area:
                    st.subheader("📝 Scan Results Summary")
                    st.markdown(f"**Discovered:** **{len(pages)}** pages and **{len(forms)}** forms.") 

                    st.subheader("🌐 HTTP Security Header Status")
                    
                    header_df = pd.DataFrame(REQUIRED_SECURITY_HEADERS, columns=['Required Header'])
                    header_df['Status'] = header_df['Required Header'].apply(lambda x: '✅ Present' if x.lower() in {k.lower():v for k,v in headers.items()} else '❌ Missing')
                    header_df['Value'] = header_df['Required Header'].apply(lambda x: headers.get(x, headers.get(x.lower(), '---')))
                    st.dataframe(header_df, use_container_width=True, hide_index=True)
                    st.caption("Note: Headers were checked on the base URL.")
                    st.markdown("---")
                    
                    if findings:
                        st.error(f"⚠️ **VULNERABILITIES FOUND! {len(findings)} issues detected.** Immediate action is required.")
                        
                        findings_df = pd.DataFrame(findings)
                        findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
                        findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
                        # Apply severity text color styling for best readability
                        def color_severity_text_dark(val):
                            if val == 'Critical': return 'color: #f44336; font-weight: bold;' 
                            if val == 'High': return 'color: #ff9800; font-weight: bold;'
                            if val == 'Medium': return 'color: #00bcd4; font-weight: bold;'
                            if val == 'Low': return 'color: #2196f3;'
                            return 'color: #f5f5f5;'

                        styled_df = findings_df.style.applymap(color_severity_text_dark, subset=['Severity'])

                        st.dataframe(styled_df, use_container_width=True, hide_index=True)
                        
                        excel_data = to_excel_report(target_input, findings)
                        st.download_button(
                            label="⬇️ Download Professional Excel Report (.xlsx)",
                            data=excel_data,
                            file_name=f"scan_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            type="secondary"
                        )
                    else:
                        st.balloons()
                        st.success("🎉 **No critical or major issues found** after advanced checks. The target appears secure.")

    elif page=="📜 History":
        st.title("📂 Scan History")
        
        # Select all data points from history
        c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
        rows = c.fetchall()
        
        if not rows:
            st.info("ℹ️ No past scan history found.")
        else:
            
            for r in rows:
                scan_id, target, date, findings_json = r
                findings = json.loads(findings_json)
                
                total_findings = len(findings)
                
                icon = "🚨" if total_findings > 0 else "🟢"
                
                with st.expander(f"{icon} Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
                    if findings:
                        findings_df = pd.DataFrame(findings)
                        findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
                        findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
                        # Background coloring for the table rows based on severity (History section uses soft background colors)
                        def color_row_by_severity(row):
                            # Use soft, dark mode friendly colors
                            color = ''
                            if row['Severity'] == 'Critical': color = '#382020' 
                            elif row['Severity'] == 'High': color = '#453220'
                            elif row['Severity'] == 'Medium': color = '#203a3a' 
                            elif row['Severity'] == 'Low': color = '#202a3a' 
                            return ['background-color: %s' % color] * len(row)

                        styled_df = findings_df.style.apply(color_row_by_severity, axis=1)

                        st.dataframe(styled_df, use_container_width=True, hide_index=True)
                        
                        excel_data = to_excel_report(target, findings)
                        st.download_button(
                            label="⬇️ Download Report (Excel)",
                            data=excel_data,
                            file_name=f"report_{scan_id}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key=f"dl_btn_{scan_id}",
                            type="secondary"
                        )
                    else:
                        st.success("✅ No vulnerabilities found in this scan.")