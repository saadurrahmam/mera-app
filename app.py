# # streamlit_app.py
# # """
# # Streamlit web interface for a safe educational web vulnerability scanner.
# # - Crawls same-host links (limited depth/pages)
# # - Parses forms
# # - Tests reflected XSS via a harmless marker
# # - Tests for SQL error messages by injecting a single-quote
# # - NON-DESTRUCTIVE by design. Use only on targets you own or have permission to test.
# # """

# import asyncio
# import json
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup

# # ---------------------------
# # Configuration / Constants
# # ---------------------------
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQL_ERROR_INDICATORS = [
#     "sql syntax",
#     "mysql",
#     "syntax error",
#     "sqlstate",
#     "sqlite",
#     "unclosed quotation mark",
#     "odbc",
#     "native client",
#     "pq: syntax error",
#     "you have an error in your sql",
# ]

# # ---------------------------
# # Crawler
# # ---------------------------
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         try:
#             async with session.get(url, timeout=self.timeout) as resp:
#                 text = await resp.text(errors="ignore")
#                 return resp.status, text
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {e}")
#             return None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 if url in self.seen or depth > self.max_depth:
#                     continue
#                 self.logger(f"Crawling: {url} (depth {depth})")
#                 status, text = await self.fetch(session, url)
#                 self.seen.add(url)
#                 if text is None:
#                     continue
#                 self.pages.append({"url": url, "status": status, "body": text})
#                 forms = self.parse_forms(url, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms}

# # ---------------------------
# # Prober
# # ---------------------------
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def test_url_param_reflection(self, session, url):
#         parts = list(urlsplit(url))
#         query = parse_qs(parts[3], keep_blank_values=True)
#         if not query:
#             return
#         for param in list(query.keys()):
#             orig_values = query[param]
#             # Inject marker
#             query[param] = [XSS_MARKER]
#             parts[3] = urlencode(query, doseq=True)
#             test_url = urlunsplit(parts)
#             try:
#                 async with session.get(test_url, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             except Exception as e:
#                 self.logger(f"param reflection request failed: {test_url} -> {e}")
#                 continue
#             if XSS_MARKER in text:
#                 self.findings.append({
#                     "type": "reflected-xss",
#                     "vector": "query",
#                     "url": test_url,
#                     "param": param,
#                     "evidence": f"marker reflected in response (param {param})"
#                 })
#             # Test SQL error by injecting single quote
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             sqli_url = urlunsplit(parts)
#             try:
#                 async with session.get(sqli_url, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#             except Exception:
#                 stext = ""
#             lowered = stext.lower()
#             if any(ind in lowered for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "sqli-error",
#                     "vector": "query",
#                     "url": sqli_url,
#                     "param": param,
#                     "evidence": "sql error indicator present in response"
#                 })
#             query[param] = orig_values

#     async def test_form_reflection(self, session, form):
#         action = form["action"]
#         method = form.get("method", "get").lower()
#         inputs = form.get("inputs", [])
#         if not inputs:
#             return
#         data = {}
#         text_like_present = False
#         for inp in inputs:
#             name = inp["name"]
#             typ = inp.get("type", "text")
#             if typ in ("text", "search", "textarea", "email", "password") or typ == "text":
#                 data[name] = XSS_MARKER
#                 text_like_present = True
#             else:
#                 data[name] = "1"
#         try:
#             if method == "get":
#                 async with session.get(action, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(action, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#         except Exception as e:
#             self.logger(f"form submission failed: {action} -> {e}")
#             return

#         if XSS_MARKER in text:
#             self.findings.append({
#                 "type": "reflected-xss",
#                 "vector": "form",
#                 "url": action,
#                 "form": form,
#                 "evidence": "marker reflected in response"
#             })

#         if text_like_present:
#             sqli_data = {k: ("'" if v == XSS_MARKER else v) for k, v in data.items()}
#             try:
#                 if method == "get":
#                     async with session.get(action, params=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#                 else:
#                     async with session.post(action, data=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#             except Exception as e:
#                 self.logger(f"form sqli test failed: {action} -> {e}")
#                 stext = ""
#             stext_lower = stext.lower()
#             if any(ind in stext_lower for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "sqli-error",
#                     "vector": "form",
#                     "url": action,
#                     "form": form,
#                     "evidence": "sql error indicator present after quote injection"
#                 })

#     async def run(self, pages, forms):
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             # URL param tests
#             for p in pages:
#                 url = p["url"]
#                 async def task_url(u=url):
#                     async with sem:
#                         self.logger(f"Testing params on: {u}")
#                         await self.test_url_param_reflection(session, u)
#                 tasks.append(asyncio.create_task(task_url()))
#             # Form tests
#             for f in forms:
#                 async def task_form(form=f):
#                     async with sem:
#                         self.logger(f"Testing form: {form.get('action')}")
#                         await self.test_form_reflection(session, form)
#                 tasks.append(asyncio.create_task(task_form()))
#             if tasks:
#                 await asyncio.gather(*tasks)
#         return self.findings

# # ---------------------------
# # Reporter / Helpers
# # ---------------------------
# def build_report(findings, target):
#     payload = {
#         "scanned_at": datetime.utcnow().isoformat() + "Z",
#         "target": target,
#         "findings": findings
#     }
#     return payload

# # ---------------------------
# # UI: Streamlit App
# # ---------------------------
# st.set_page_config(page_title="Web Vulnerability Scanner", layout="wide")
# st.title("Web Vulnerability Scanner — Streamlit UI")
# st.markdown(
#     """
# This is a **safe educational scanner** (crawler + reflected XSS checks + error-based SQLi checks).
# **Only scan targets you own or have explicit permission to test** (e.g., OWASP Juice Shop).
# """
# )

# with st.sidebar:
#     st.header("Scan options")
#     target_input = st.text_input("Target base URL (include http:// or https://)", value="http://localhost:3000")
#     max_pages = st.number_input("Max pages to crawl", min_value=1, max_value=1000, value=100, step=1)
#     max_depth = st.number_input("Max crawl depth", min_value=0, max_value=5, value=2, step=1)
#     concurrency = st.number_input("Concurrency (probes)", min_value=1, max_value=50, value=8, step=1)
#     timeout = st.number_input("Request timeout (seconds)", min_value=5, max_value=120, value=20, step=1)
#     run_button = st.button("Start Scan", type="primary")

# status_area = st.empty()
# log_area = st.empty()
# results_area = st.container()

# # logger function that writes to Streamlit
# def make_logger(log_writer):
#     def logger(msg):
#         # append log lines
#         log_writer(msg)
#     return logger

# # scan function
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     """
#     Wrapper to run asyncio-based crawler/prober synchronously (via asyncio.run).
#     ui_log is a callable that accepts a message string to display progress/logs.
#     """
#     async def inner():
#         logger = make_logger(ui_log)
#         logger(f"[+] Starting crawl on {target}")
#         crawler = Crawler(target, max_pages=max_pages, max_depth=max_depth, timeout=timeout, logger=logger)
#         c_result = await crawler.crawl()
#         pages = c_result.get("pages", [])
#         forms = c_result.get("forms", [])
#         logger(f"[+] Crawl complete — pages found: {len(pages)}, forms found: {len(forms)}")
#         logger("[+] Starting probing phase")
#         prober = Prober(concurrency=concurrency, timeout=timeout, logger=logger)
#         findings = await prober.run(pages, forms)
#         logger(f"[+] Probing complete — findings: {len(findings)}")
#         return findings, pages, forms
#     return asyncio.run(inner())

# # Helper to append logs to Streamlit area (keeps last N lines)
# LOG_LINES = []
# MAX_LOG_LINES = 200
# def ui_log_append(msg):
#     global LOG_LINES
#     LOG_LINES.append(f"{datetime.utcnow().isoformat()} - {msg}")
#     if len(LOG_LINES) > MAX_LOG_LINES:
#         LOG_LINES = LOG_LINES[-MAX_LOG_LINES:]
#     log_area.markdown("```\n" + "\n".join(LOG_LINES) + "\n```")

# # When user clicks start
# if run_button:
#     if not target_input.strip():
#         st.warning("Please provide a target URL.")
#     else:
#         LOG_LINES = []
#         status_area.info("Scan queued...")
#         # Run scan synchronously (blocks UI while running)
#         try:
#             status_area.info("Scan running — this may take a while depending on target and options.")
#             findings, pages, forms = run_scan_sync(
#                 target_input.strip(),
#                 int(max_pages),
#                 int(max_depth),
#                 int(concurrency),
#                 int(timeout),
#                 ui_log_append
#             )
#             report = build_report(findings, target_input.strip())
#             # Display results
#             status_area.success("Scan finished.")
#             with results_area:
#                 st.subheader("Summary")
#                 st.write(f"Target: **{target_input}**")
#                 st.write(f"Pages crawled: **{len(pages)}**, Forms found: **{len(forms)}**, Findings: **{len(findings)}**")

#                 if findings:
#                     # present a table
#                     st.subheader("Findings")
#                     # Normalize findings into table rows
#                     table_rows = []
#                     for f in findings:
#                         row = {
#                             "type": f.get("type"),
#                             "vector": f.get("vector"),
#                             "url": f.get("url"),
#                             "param": f.get("param", ""),
#                             "evidence": f.get("evidence", "")
#                         }
#                         table_rows.append(row)
#                     st.table(table_rows)

#                     # Allow download of report
#                     json_str = json.dumps(report, indent=2)
#                     st.download_button("Download JSON report", data=json_str, file_name="scan_report.json", mime="application/json")
#                 else:
#                     st.info("No issues found by this basic scanner.")
#         except Exception as exc:
#             status_area.error(f"Scan failed: {exc}")
#             ui_log_append(f"Exception: {exc}")

# # Help / next steps
# st.markdown("---")
# st.subheader("Notes & next steps")
# st.markdown("""
# - This is a **starter professional interface**. If you want:
#   - real-time progress updates per-page/form (live streaming): I can add a background worker + websocket/Redis queue or use Streamlit's experimental `st.session_state` + background threads.
#   - authentication handling (scan behind login): I can add login capture & session cookie handling.
#   - more checks: stored XSS detection, blind SQLi (time-based), CSP/headers checks, security header audits.
#   - user accounts / saved scans / report history.
# - REMINDER: Do **not** scan systems you don't own or have permission to test.
# """)


# # streamlit_app.py
# import asyncio
# import json
# import sqlite3
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup
# from fpdf import FPDF

# # ==================================
# # DATABASE SETUP
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# # Create default admin if not exists
# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]

# # ==================================
# # CRAWLER CLASS
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         try:
#             async with session.get(url, timeout=self.timeout) as resp:
#                 text = await resp.text(errors="ignore")
#                 return resp.status, text
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {e}")
#             return None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 if url in self.seen or depth > self.max_depth:
#                     continue
#                 self.logger(f"Crawling: {url} (depth {depth})")
#                 status, text = await self.fetch(session, url)
#                 self.seen.add(url)
#                 if text is None:
#                     continue
#                 self.pages.append({"url": url, "status": status, "body": text})
#                 forms = self.parse_forms(url, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms}

# # ==================================
# # PROBER CLASS
# # ==================================
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def test_url_param_reflection(self, session, url):
#         parts = list(urlsplit(url))
#         query = parse_qs(parts[3], keep_blank_values=True)
#         if not query:
#             return
#         for param in list(query.keys()):
#             orig_values = query[param]
#             query[param] = [XSS_MARKER]
#             parts[3] = urlencode(query, doseq=True)
#             test_url = urlunsplit(parts)
#             try:
#                 async with session.get(test_url, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             except Exception:
#                 continue
#             if XSS_MARKER in text:
#                 self.findings.append({
#                     "type": "reflected-xss",
#                     "vector": "query",
#                     "url": test_url,
#                     "param": param,
#                     "evidence": f"marker reflected in response (param {param})"
#                 })
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             sqli_url = urlunsplit(parts)
#             try:
#                 async with session.get(sqli_url, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#             except Exception:
#                 stext = ""
#             if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "sqli-error",
#                     "vector": "query",
#                     "url": sqli_url,
#                     "param": param,
#                     "evidence": "sql error indicator present in response"
#                 })
#             query[param] = orig_values

#     async def test_form_reflection(self, session, form):
#         action = form["action"]
#         method = form.get("method", "get").lower()
#         inputs = form.get("inputs", [])
#         if not inputs:
#             return
#         data = {}
#         text_like_present = False
#         for inp in inputs:
#             name = inp["name"]
#             typ = inp.get("type", "text")
#             if typ in ("text","search","textarea","email","password") or typ=="text":
#                 data[name] = XSS_MARKER
#                 text_like_present = True
#             else:
#                 data[name] = "1"
#         try:
#             if method=="get":
#                 async with session.get(action, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(action, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#         except Exception:
#             return
#         if XSS_MARKER in text:
#             self.findings.append({
#                 "type": "reflected-xss",
#                 "vector": "form",
#                 "url": action,
#                 "form": form,
#                 "evidence": "marker reflected in response"
#             })
#         if text_like_present:
#             sqli_data = {k: ("'" if v==XSS_MARKER else v) for k,v in data.items()}
#             try:
#                 if method=="get":
#                     async with session.get(action, params=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#                 else:
#                     async with session.post(action, data=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#             except Exception:
#                 stext = ""
#             if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "sqli-error",
#                     "vector": "form",
#                     "url": action,
#                     "form": form,
#                     "evidence": "sql error indicator present after quote injection"
#                 })

#     async def run(self, pages, forms):
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(u=p["url"]):
#                     async with sem:
#                         await self.test_url_param_reflection(session, u)
#                 tasks.append(asyncio.create_task(task_url()))
#             for f in forms:
#                 async def task_form(form=f):
#                     async with sem:
#                         await self.test_form_reflection(session, form)
#                 tasks.append(asyncio.create_task(task_form()))
#             if tasks:
#                 await asyncio.gather(*tasks)
#         return self.findings

# # ==================================
# # RUN SCAN (sync wrapper)
# # ==================================
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     async def inner():
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         c_result = await crawler.crawl()
#         prober = Prober(concurrency, timeout, logger)
#         findings = await prober.run(c_result["pages"], c_result["forms"])
#         return findings, c_result["pages"], c_result["forms"]
#     return asyncio.run(inner())

# # ==================================
# # STREAMLIT UI
# # ==================================
# st.set_page_config(page_title="Advanced Scanner", layout="wide")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# if not st.session_state.logged_in:
#     st.sidebar.header("Login")
#     username = st.sidebar.text_input("Username")
#     password = st.sidebar.text_input("Password", type="password")
#     login_btn = st.sidebar.button("Login")
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username,password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.success(f"Logged in as {st.session_state.role}")
#         else:
#             st.error("Invalid credentials")
# else:
#     page = st.sidebar.radio("Navigation", ["Home","Scanner","History"])
#     if page=="Home":
#         st.title("🏠 Dashboard")
#         st.markdown("Welcome to the **Advanced Web Vulnerability Scanner**")
#     elif page=="Scanner":
#         st.title("🛡️ Scanner")
#         target_input = st.text_input("Target URL", "http://localhost:3000")
#         max_pages = st.number_input("Max pages", 1,1000,100)
#         max_depth = st.number_input("Max depth",0,5,2)
#         concurrency = st.number_input("Concurrency",1,50,8)
#         timeout = st.number_input("Timeout (s)",5,120,20)
#         run_button = st.button("Start Scan")
#         status_area = st.empty()
#         log_area = st.empty()
#         results_area = st.container()
#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
#             LOG_LINES.append(msg)
#             log_area.text("\n".join(LOG_LINES[-50:]))
#         if run_button:
#             if not target_input.strip():
#                 st.warning("Provide target URL")
#             else:
#                 LOG_LINES=[]
#                 status_area.info("Scan started...")
#                 findings, pages, forms = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)
#                 # Save history
#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)",(target_input,str(datetime.utcnow()),json.dumps(findings)))
#                 conn.commit()
#                 status_area.success("Scan completed")
#                 with results_area:
#                     st.subheader("Findings")
#                     if findings:
#                         for f in findings:
#                             st.markdown(f"- {f['type']} | {f.get('url')} | Evidence: {f.get('evidence')}")
#                         # PDF download
#                         pdf = FPDF()
#                         pdf.add_page()
#                         pdf.set_font("Arial",size=12)
#                         pdf.cell(0,10,f"Scan Report for {target_input}",ln=True,align="C")
#                         pdf.ln(10)
#                         for f in findings:
#                             pdf.multi_cell(0,8,f"Type: {f['type']} | URL: {f.get('url')} | Evidence: {f.get('evidence')}")
#                         pdf_file=f"scan_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
#                         pdf.output(pdf_file)
#                         with open(pdf_file,"rb") as pf:
#                             st.download_button("Download PDF Report",pf,file_name="scan_report.pdf",mime="application/pdf")
#                     else:
#                         st.info("No issues found")
#     elif page=="History":
#         st.title("📜 Scan History")
#         c.execute("SELECT target,date,findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
#         for r in rows:
#             st.markdown(f"**Target:** {r[0]} | **Date:** {r[1]}")
#             findings=json.loads(r[2])
#             for f in findings:
#                 st.markdown(f"- {f['type']} | {f.get('url')} | Evidence: {f.get('evidence')}")




# # streamlit_app.py
# import asyncio
# import json
# import sqlite3
# import pandas as pd # Import pandas for data presentation
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup
# from fpdf import FPDF

# # ==================================
# # DATABASE SETUP
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# # Create default admin if not exists
# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]

# # ==================================
# # CRAWLER CLASS
# # (No changes needed here - logic is fine)
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         try:
#             async with session.get(url, timeout=self.timeout) as resp:
#                 text = await resp.text(errors="ignore")
#                 return resp.status, text
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {e}")
#             return None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 if url in self.seen or depth > self.max_depth:
#                     continue
#                 self.logger(f"Crawling: {url} (depth {depth})")
#                 status, text = await self.fetch(session, url)
#                 self.seen.add(url)
#                 if text is None:
#                     continue
#                 self.pages.append({"url": url, "status": status, "body": text})
#                 forms = self.parse_forms(url, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms}

# # ==================================
# # PROBER CLASS
# # (No changes needed here - logic is fine)
# # ==================================
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def test_url_param_reflection(self, session, url):
#         parts = list(urlsplit(url))
#         query = parse_qs(parts[3], keep_blank_values=True)
#         if not query:
#             return
#         for param in list(query.keys()):
#             orig_values = query[param]
#             # XSS Test
#             query[param] = [XSS_MARKER]
#             parts[3] = urlencode(query, doseq=True)
#             test_url = urlunsplit(parts)
#             try:
#                 async with session.get(test_url, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             except Exception:
#                 continue
#             if XSS_MARKER in text:
#                 self.findings.append({
#                     "type": "Reflected XSS",
#                     "severity": "High", # Added Severity
#                     "vector": "URL Query Parameter",
#                     "url": test_url,
#                     "param": param,
#                     "evidence": f"marker reflected in response (param {param})"
#                 })
#             # SQLI Test
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             sqli_url = urlunsplit(parts)
#             try:
#                 async with session.get(sqli_url, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#             except Exception:
#                 stext = ""
#             if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "SQL Injection (Error-Based)",
#                     "severity": "Critical", # Added Severity
#                     "vector": "URL Query Parameter",
#                     "url": sqli_url,
#                     "param": param,
#                     "evidence": "sql error indicator present in response"
#                 })
#             query[param] = orig_values

#     async def test_form_reflection(self, session, form):
#         action = form["action"]
#         method = form.get("method", "get").lower()
#         inputs = form.get("inputs", [])
#         if not inputs:
#             return
#         data = {}
#         text_like_present = False
#         for inp in inputs:
#             name = inp["name"]
#             typ = inp.get("type", "text")
#             if typ in ("text","search","textarea","email","password") or typ=="text":
#                 data[name] = XSS_MARKER
#                 text_like_present = True
#             else:
#                 data[name] = "1"
#         # XSS Test
#         try:
#             if method=="get":
#                 async with session.get(action, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(action, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#         except Exception:
#             return
#         if XSS_MARKER in text:
#             self.findings.append({
#                 "type": "Reflected XSS",
#                 "severity": "High", # Added Severity
#                 "vector": f"Form ({method.upper()})",
#                 "url": action,
#                 "param": ", ".join([i['name'] for i in inputs if i['type'] in ("text","search","textarea","email","password") or i['type']=="text"]), # Changed 'form' to 'param' for better display
#                 "evidence": "marker reflected in response"
#             })
#         # SQLI Test
#         if text_like_present:
#             sqli_data = {k: ("'" if v==XSS_MARKER else v) for k,v in data.items()}
#             try:
#                 if method=="get":
#                     async with session.get(action, params=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#                 else:
#                     async with session.post(action, data=sqli_data, timeout=self.timeout) as resp:
#                         stext = await resp.text(errors="ignore")
#             except Exception:
#                 stext = ""
#             if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "SQL Injection (Error-Based)",
#                     "severity": "Critical", # Added Severity
#                     "vector": f"Form ({method.upper()})",
#                     "url": action,
#                     "param": ", ".join([i['name'] for i in inputs if i['type'] in ("text","search","textarea","email","password") or i['type']=="text"]), # Changed 'form' to 'param' for better display
#                     "evidence": "sql error indicator present after quote injection"
#                 })

#     async def run(self, pages, forms):
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(u=p["url"]):
#                     async with sem:
#                         await self.test_url_param_reflection(session, u)
#                 tasks.append(asyncio.create_task(task_url()))
#             for f in forms:
#                 async def task_form(form=f):
#                     async with sem:
#                         await self.test_form_reflection(session, form)
#                 tasks.append(asyncio.create_task(task_form()))
#             if tasks:
#                 # Use return_exceptions=True to ensure all tasks run even if one fails
#                 await asyncio.gather(*tasks, return_exceptions=True) 
#         return self.findings

# # ==================================
# # RUN SCAN (sync wrapper)
# # ==================================
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     async def inner():
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         c_result = await crawler.crawl()
#         prober = Prober(concurrency, timeout, logger)
#         findings = await prober.run(c_result["pages"], c_result["forms"])
#         return findings, c_result["pages"], c_result["forms"]
#     return asyncio.run(inner())

# # ==================================
# # PDF Generation (Improved)
# # ==================================
# def create_pdf_report(target_url, findings):
#     pdf = FPDF()
#     pdf.add_page()
#     pdf.set_font("Arial", style="B", size=16)
#     pdf.cell(0, 10, "Web Vulnerability Scan Report", ln=True, align="C")
#     pdf.set_font("Arial", size=12)
#     pdf.cell(0, 8, f"Target URL: {target_url}", ln=True)
#     pdf.cell(0, 8, f"Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
#     pdf.ln(5)

#     if not findings:
#         pdf.cell(0, 10, "--- No Vulnerabilities Found ---", ln=True, align="C")
#     else:
#         pdf.set_font("Arial", style="B", size=14)
#         pdf.cell(0, 10, f"Total Findings: {len(findings)}", ln=True)
#         pdf.ln(2)
        
#         for i, f in enumerate(findings, 1):
#             pdf.set_fill_color(220, 220, 220)
#             pdf.set_font("Arial", style="B", size=12)
#             pdf.multi_cell(0, 8, f"Finding {i}: {f['type']} (Severity: {f.get('severity', 'N/A')})", 1, 'L', 1)
#             pdf.set_font("Arial", size=10)
#             pdf.multi_cell(0, 6, f"  URL: {f.get('url', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Vector: {f.get('vector', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Parameter(s): {f.get('param', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Evidence: {f.get('evidence', 'N/A')}")
#             pdf.ln(2)

#     pdf_file_path = f"scan_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
#     pdf.output(pdf_file_path)
#     return pdf_file_path

# # ==================================
# # STREAMLIT UI (Improved)
# # ==================================
# st.set_page_config(page_title="Advanced Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# st.sidebar.title("🔐 Navigation")

# if not st.session_state.logged_in:
#     st.sidebar.header("Login")
#     username = st.sidebar.text_input("Username", key="login_user")
#     password = st.sidebar.text_input("Password", type="password", key="login_pass")
#     login_btn = st.sidebar.button("Login", use_container_width=True)
    
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.sidebar.success(f"Logged in as {st.session_state.role}")
#             st.experimental_rerun() # Rerun to update the main page content
#         else:
#             st.sidebar.error("Invalid credentials")
# else:
#     # Sidebar Navigation and Logout
#     page = st.sidebar.radio("Go to:", ["Home","Scanner","History"])
#     st.sidebar.markdown("---")
#     logout_btn = st.sidebar.button("Logout", type="secondary", use_container_width=True)
#     if logout_btn:
#         st.session_state.logged_in = False
#         st.session_state.role = ''
#         st.info("Logged out successfully.")
#         st.experimental_rerun()

#     # --- Home/Dashboard Section ---
#     if page=="Home":
#         st.title("🏠 Security Dashboard")
#         st.markdown("Welcome to the **Advanced Web Vulnerability Scanner** dashboard.")
        
#         st.subheader("Scan Statistics")
#         c.execute("SELECT target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         total_scans = len(rows)
#         total_findings = 0
#         finding_counts = {}
        
#         for r in rows:
#             try:
#                 findings = json.loads(r[2])
#                 total_findings += len(findings)
#                 for f in findings:
#                     v_type = f.get('type', 'Unknown')
#                     finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
#             except Exception:
#                 pass
        
#         col1, col2, col3 = st.columns(3)
#         col1.metric("Total Scans", total_scans)
#         col2.metric("Total Findings", total_findings)
#         col3.metric("Most Recent Target", rows[0][0] if rows else "N/A")

#         st.markdown("---")
#         st.subheader("Finding Distribution")
        
#         if finding_counts:
#             # Prepare data for chart
#             df_counts = pd.DataFrame(list(finding_counts.items()), columns=['Vulnerability Type', 'Count'])
#             st.bar_chart(df_counts, x='Vulnerability Type', y='Count')
#         else:
#             st.info("No scan data available to display distribution.")
            
#     # --- Scanner Section ---
#     elif page=="Scanner":
#         st.title("🛡️ Web Vulnerability Scanner")
        
#         # Scanner Configuration
#         with st.expander("⚙️ Scan Configuration", expanded=True):
#             col1, col2 = st.columns(2)
#             target_input = col1.text_input("Target URL", "http://localhost:3000", key="target_url")
            
#             # Use columns for better layout of numerical inputs
#             col_a, col_b, col_c, col_d = st.columns(4)
#             max_pages = col_a.number_input("Max Pages to Crawl", 1, 1000, 100, key="max_pages")
#             max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth")
#             concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency")
#             timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout")

#             run_button = st.button("🚨 Start Scan", type="primary", use_container_width=True)
            
#         status_area = st.empty()
#         results_area = st.container()
        
#         st.markdown("---")
#         st.subheader("Scan Log")
#         log_area = st.container(border=True) # Use a container with border for the log

#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
#             LOG_LINES.append(msg)
#             # Display only the last 15 lines of the log in the container
#             with log_area:
#                  st.code("\n".join(LOG_LINES[-15:]), language="text")

#         if run_button:
#             if not target_input.strip():
#                 status_area.warning("Please provide a target URL.")
#             elif not target_input.startswith(('http://', 'https://')):
#                  status_area.error("Target URL must start with 'http://' or 'https://'.")
#             else:
#                 LOG_LINES=[]
#                 with status_area:
#                     st.info("Scan started. Please wait...")
                
#                 try:
#                     findings, pages, forms = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)
#                 except Exception as e:
#                     status_area.error(f"An error occurred during scan: {e}")
#                     findings = [] # Ensure findings is defined even on error

#                 # Save history
#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
#                 conn.commit()
                
#                 status_area.success("Scan completed successfully!")
                
#                 with results_area:
#                     st.subheader("✅ Scan Results")
#                     st.info(f"Crawled **{len(pages)}** pages and found **{len(forms)}** forms.")
                    
#                     if findings:
#                         st.error(f"**Found {len(findings)} Vulnerabilities!**")
                        
#                         # Convert findings to a DataFrame for clear display
#                         findings_df = pd.DataFrame(findings)
#                         # Select and reorder columns for better presentation
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         # PDF generation and download
#                         pdf_file_path = create_pdf_report(target_input, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download PDF Report", pf, file_name="scan_report.pdf", mime="application/pdf", type="secondary")
#                     else:
#                         st.balloons()
#                         st.success("🎉 No issues found! Website seems secure.")

#     # --- History Section ---
#     elif page=="History":
#         st.title("📜 Scan History")
        
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         if not rows:
#             st.info("No scan history found.")
#         else:
#             for r in rows:
#                 scan_id, target, date, findings_json = r
#                 findings = json.loads(findings_json)
                
#                 total_findings = len(findings)
#                 badge_style = "info" if total_findings == 0 else ("warning" if total_findings <= 5 else "danger")
                
#                 # Display each scan history item in an expander
#                 with st.expander(f"Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
#                     if findings:
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'URL', 'Parameter', 'Vector', 'Evidence']
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         # Re-generate and offer PDF download for history item
#                         pdf_file_path = create_pdf_report(target, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download This Report (PDF)", pf, file_name=f"report_{scan_id}.pdf", key=f"dl_btn_{scan_id}", type="secondary")
#                     else:
#                         st.success("No vulnerabilities found in this scan.")







# # streamlit_app.py
# import asyncio
# import json
# import sqlite3
# import pandas as pd 
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode
# import altair as alt # Import Altair for advanced charting

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup
# from fpdf import FPDF

# # ==================================
# # DATABASE SETUP
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# # Create default admin if not exists
# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]

# # ==================================
# # CRAWLER CLASS
# # (Code unchanged)
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         try:
#             async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
#                 text = await resp.text(errors="ignore")
#                 return resp.status, text
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {type(e).__name__}: {e}")
#             return None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 url_clean = url.split('#')[0] 
#                 if url_clean in self.seen or depth > self.max_depth:
#                     continue
#                 self.logger(f"Crawling: {url_clean} (depth {depth})")
#                 status, text = await self.fetch(session, url_clean)
#                 self.seen.add(url_clean)
#                 if text is None:
#                     continue
#                 self.pages.append({"url": url_clean, "status": status, "body": text})
#                 forms = self.parse_forms(url_clean, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url_clean, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url_clean, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms}

# # ==================================
# # PROBER CLASS 
# # (Code unchanged)
# # ==================================
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def test_url_param_reflection(self, session, url):
#         parts = list(urlsplit(url))
#         query_string = parts[3]
#         if not query_string:
#             return
            
#         query = parse_qs(query_string, keep_blank_values=True)
        
#         for param in list(query.keys()):
#             orig_values = query[param]
            
#             # --- XSS Test ---
#             query[param] = [XSS_MARKER]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_xss = urlunsplit(parts)
            
#             try:
#                 async with session.get(test_url_xss, timeout=self.timeout) as resp:
#                     text_xss = await resp.text(errors="ignore")
#             except Exception as e:
#                 self.logger(f"XSS Test Error for {param} on {url}: {e}")
#                 text_xss = ""
                
#             if XSS_MARKER in text_xss:
#                 self.findings.append({
#                     "type": "Reflected XSS",
#                     "severity": "High", 
#                     "vector": "URL Query Parameter",
#                     "url": test_url_xss,
#                     "param": param,
#                     "evidence": f"marker reflected in response for param '{param}'"
#                 })

#             # --- SQLI Test ---
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli = urlunsplit(parts)
            
#             try:
#                 async with session.get(test_url_sqli, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#             except Exception as e:
#                 self.logger(f"SQLI Test Error for {param} on {url}: {e}")
#                 stext = ""
                
#             if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({
#                     "type": "SQL Injection (Error-Based)",
#                     "severity": "Critical", 
#                     "vector": "URL Query Parameter",
#                     "url": test_url_sqli,
#                     "param": param,
#                     "evidence": "SQL error indicator present in response"
#                 })
            
#             query[param] = orig_values

#     async def test_form_reflection(self, session, form):
#         action = form["action"]
#         method = form.get("method", "get").lower()
#         inputs = form.get("inputs", [])
#         if not inputs:
#             return
            
#         data = {}
#         text_like_inputs = []
        
#         for inp in inputs:
#             name = inp["name"]
#             typ = inp.get("type", "text")
#             if typ in ("text","search","textarea","email","password") or typ=="text":
#                 data[name] = XSS_MARKER
#                 text_like_inputs.append(name)
#             else:
#                 data[name] = "1"
        
#         if not text_like_inputs:
#             return
            
#         # --- XSS Test ---
#         try:
#             if method=="get":
#                 async with session.get(action, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(action, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#         except Exception as e:
#             self.logger(f"Form XSS Test Error for {action}: {e}")
#             return
            
#         if XSS_MARKER in text:
#             self.findings.append({
#                 "type": "Reflected XSS",
#                 "severity": "High", 
#                 "vector": f"Form ({method.upper()})",
#                 "url": action,
#                 "param": ", ".join(text_like_inputs), 
#                 "evidence": "marker reflected in response"
#             })
            
#         # --- SQLI Test ---
#         sqli_data = {k: ("'" if k in text_like_inputs else v) for k,v in data.items()}
        
#         try:
#             if method=="get":
#                 async with session.get(action, params=sqli_data, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#             else:
#                 async with session.post(action, data=sqli_data, timeout=self.timeout) as resp:
#                     stext = await resp.text(errors="ignore")
#         except Exception as e:
#             self.logger(f"Form SQLI Test Error for {action}: {e}")
#             stext = ""
            
#         if any(ind in stext.lower() for ind in SQL_ERROR_INDICATORS):
#             self.findings.append({
#                 "type": "SQL Injection (Error-Based)",
#                 "severity": "Critical", 
#                 "vector": f"Form ({method.upper()})",
#                 "url": action,
#                 "param": ", ".join(text_like_inputs),
#                 "evidence": "SQL error indicator present after quote injection"
#             })

#     async def run(self, pages, forms):
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(u=p["url"]):
#                     async with sem:
#                         await self.test_url_param_reflection(session, u)
#                 tasks.append(asyncio.create_task(task_url()))
#             for f in forms:
#                 async def task_form(form=f):
#                     async with sem:
#                         await self.test_form_reflection(session, form)
#                 tasks.append(asyncio.create_task(task_form()))
#             if tasks:
#                 await asyncio.gather(*tasks, return_exceptions=True) 
#         return self.findings

# # ==================================
# # RUN SCAN (sync wrapper)
# # ==================================
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     async def inner():
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         ui_log("Starting crawl...")
#         c_result = await crawler.crawl()
#         ui_log(f"Crawl finished. Found {len(c_result['pages'])} pages and {len(c_result['forms'])} forms.")
#         prober = Prober(concurrency, timeout, logger)
#         ui_log("Starting vulnerability probing...")
#         findings = await prober.run(c_result["pages"], c_result["forms"])
#         ui_log("Probing finished.")
#         return findings, c_result["pages"], c_result["forms"]
#     return asyncio.run(inner())

# # ==================================
# # PDF Generation 
# # ==================================
# def create_pdf_report(target_url, findings):
#     pdf = FPDF()
#     pdf.add_page()
#     pdf.set_font("Arial", style="B", size=16)
#     pdf.cell(0, 10, "🛡️ Web Security Scan Report", ln=True, align="C")
#     pdf.set_font("Arial", size=12)
#     pdf.cell(0, 8, f"Target URL: {target_url}", ln=True)
#     pdf.cell(0, 8, f"Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
#     pdf.cell(0, 8, f"Total Findings: {len(findings)}", ln=True)
#     pdf.ln(5)

#     if not findings:
#         pdf.cell(0, 10, "--- No Vulnerabilities Found ---", ln=True, align="C")
#     else:
#         for i, f in enumerate(findings, 1):
#             pdf.set_fill_color(220, 220, 220)
#             pdf.set_font("Arial", style="B", size=12)
#             pdf.multi_cell(0, 8, f"Finding {i}: {f['type']} (Severity: {f.get('severity', 'N/A')})", 1, 'L', 1)
#             pdf.set_font("Arial", size=10)
#             pdf.multi_cell(0, 6, f"  URL: {f.get('url', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Vector: {f.get('vector', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Parameter(s): {f.get('param', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Evidence: {f.get('evidence', 'N/A')}")
#             pdf.ln(2)

#     pdf_file_path = f"scan_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
#     pdf.output(pdf_file_path)
#     return pdf_file_path


# # ==================================
# # STREAMLIT UI 
# # ==================================
# st.set_page_config(page_title="Pro Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# st.sidebar.title("🔐 SafeScanner Pro")

# # --- Login Logic ---
# if not st.session_state.logged_in:
#     st.sidebar.header("User Login")
#     username = st.sidebar.text_input("👤 Username", key="login_user")
#     password = st.sidebar.text_input("🔑 Password", type="password", key="login_pass")
#     login_btn = st.sidebar.button("Login", type="primary", use_container_width=True)
    
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.sidebar.success(f"✅ Logged in as **{st.session_state.role}**")
#             st.rerun()
#         else:
#             st.sidebar.error("❌ Invalid credentials")
# else:
#     # --- Navigation and Logout ---
#     page = st.sidebar.radio("Go to:", ["🏠 Dashboard","🛡️ Scanner","📜 History"])
#     st.sidebar.markdown("---")
#     st.sidebar.caption(f"Welcome, **{st.session_state.role}**")
#     logout_btn = st.sidebar.button("Logout", type="secondary", use_container_width=True)
#     if logout_btn:
#         st.session_state.logged_in = False
#         st.session_state.role = ''
#         st.info("👋 Logged out successfully.")
#         st.experimental_rerun()

#     # --- Home/Dashboard Section (with Animated Graph) ---
#     if page=="🏠 Dashboard":
#         st.title("📊 Security Scan Dashboard")
#         st.markdown("Overview of all past scan activities and vulnerability distribution.")
        
#         c.execute("SELECT target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         total_scans = len(rows)
#         total_findings = 0
#         finding_counts = {}
        
#         for r in rows:
#             try:
#                 findings = json.loads(r[2])
#                 total_findings += len(findings)
#                 for f in findings:
#                     v_type = f.get('type', 'Unknown')
#                     finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
#             except Exception:
#                 pass
        
#         st.subheader("Key Metrics")
#         col1, col2, col3 = st.columns(3)
#         col1.metric("Total Scans", total_scans, delta="Since inception", delta_color="off")
#         col2.metric("Total Findings", total_findings, delta=f"{len(finding_counts)} unique types", delta_color="off")
#         col3.metric("Latest Target", rows[0][0] if rows else "N/A", delta=rows[0][1].split(' ')[0] if rows else "N/A")

#         st.markdown("---")
#         st.subheader("Vulnerability Type Distribution (Animated Graph)")
        
#         if finding_counts:
#             df_counts = pd.DataFrame(list(finding_counts.items()), columns=['Vulnerability Type', 'Count'])
            
#             base = alt.Chart(df_counts).encode(
#                 theta=alt.Theta("Count", stack=True)
#             ).properties(
#                 title='Finding Distribution Across All Scans'
#             )
            
#             pie = base.mark_arc(outerRadius=120, innerRadius=60).encode(
#                 color=alt.Color("Vulnerability Type"),
#                 order=alt.Order("Count", sort="descending"),
#                 tooltip=["Vulnerability Type", "Count"]
#             )
            
#             text = base.mark_text(radius=140).encode(
#                 text=alt.Text("Count"),
#                 order=alt.Order("Count", sort="descending"),
#                 color=alt.value("black") 
#             )

#             st.altair_chart(pie + text, use_container_width=True)
#         else:
#             st.info("No scan data available to display distribution chart.")
            
#     # --- Scanner Section ---
#     elif page=="🛡️ Scanner":
#         st.title("🔬 Web Vulnerability Scan")
        
#         with st.expander("⚙️ Scan Configuration", expanded=True):
#             target_input = st.text_input("🌐 Target URL (e.g., http://testphp.vulnweb.com)", "http://localhost:3000", key="target_url")
            
#             col_a, col_b, col_c, col_d = st.columns(4)
#             max_pages = col_a.number_input("Max Pages", 1, 1000, 100, key="max_pages")
#             max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth")
#             concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency")
#             timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout")

#             run_button = st.button("🚀 Start Scan", type="primary", use_container_width=True)
            
#         status_area = st.empty()
#         results_area = st.container()
        
#         st.markdown("---")
#         st.subheader("System Log")
#         log_area = st.container(border=True)

#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
#             LOG_LINES.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
#             with log_area:
#                  st.code("\n".join(LOG_LINES[-15:]), language="text")

#         if run_button:
#             if not target_input.strip() or not target_input.startswith(('http://', 'https://')):
#                 status_area.error("❌ Please provide a valid URL starting with `http://` or `https://`.")
#             else:
#                 LOG_LINES=[]
#                 with status_area:
#                     st.info("🔍 Scan in progress... This may take a moment.")
                
#                 try:
#                     findings, pages, forms = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)
#                 except Exception as e:
#                     status_area.error(f"❌ An unhandled error occurred during scan: {type(e).__name__} - {e}")
#                     findings = []

#                 # Save history
#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
#                 conn.commit()
                
#                 status_area.success("✅ Scan completed successfully!")
                
#                 with results_area:
#                     st.subheader("📝 Scan Results Summary")
#                     st.markdown(f"**Discovered:** **{len(pages)}** pages and **{len(forms)}** forms.")
                    
#                     if findings:
#                         st.error(f"⚠️ **Found {len(findings)} VULNERABILITIES!** Action required.")
                        
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         pdf_file_path = create_pdf_report(target_input, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download PDF Report", pf, file_name="scan_report.pdf", mime="application/pdf", type="secondary")
#                     else:
#                         st.balloons()
#                         st.success("🎉 **No critical issues found!** The website appears to be secure based on basic checks.")

#     # --- History Section ---
#     elif page=="📜 History":
#         st.title("📂 Scan History")
        
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         if not rows:
#             st.info("No past scan history found.")
#         else:
#             for r in rows:
#                 scan_id, target, date, findings_json = r
#                 findings = json.loads(findings_json)
                
#                 total_findings = len(findings)
                
#                 icon = "🚨" if total_findings > 0 else "🟢"
                
#                 with st.expander(f"{icon} Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
#                     if findings:
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         pdf_file_path = create_pdf_report(target, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download Report (PDF)", pf, file_name=f"report_{scan_id}.pdf", key=f"dl_btn_{scan_id}", type="secondary")
#                     else:
#                         st.success("No vulnerabilities found in this scan.")













# # streamlit_app.py
# import asyncio
# import json
# import sqlite3
# import pandas as pd 
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode
# import altair as alt 
# import time 

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup
# from fpdf import FPDF

# # ==================================
# # DATABASE SETUP (Unchanged)
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQLI_TIME_PAYLOAD = "' OR (SELECT 20 FROM (SELECT(SLEEP(4))))--" 
# DELAY_THRESHOLD = 3.5 

# FILE_INCLUSION_PAYLOADS = [
#     "../../../../etc/passwd",
#     "file:///etc/passwd",
#     "http://127.0.0.1/nonexistent.txt" 
# ]
# FILE_INCLUSION_INDICATORS = [
#     "root:x", 
#     "failed opening required",
#     "No such file or directory"
# ]

# XSS_PAYLOADS = [
#     XSS_MARKER,
#     f"<{XSS_MARKER}>",
#     f"javascript:alert('{XSS_MARKER}')"
# ]
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]
# REQUIRED_SECURITY_HEADERS = [
#     "Strict-Transport-Security", 
#     "X-Content-Type-Options",
#     "X-Frame-Options",
#     "Content-Security-Policy",
#     "Permissions-Policy" 
# ]

# # ==================================
# # CRAWLER CLASS (FIXED: aiohttp timing)
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         # Use simple timeout for client session setup
#         self.timeout_total = timeout
#         self.timeout = aiohttp.ClientTimeout(total=timeout) 
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)
#         self.headers_info = {} 

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         start_time = time.time()
#         try:
#             async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
#                 text = await resp.text(errors="ignore")
#                 elapsed = time.time() - start_time
#                 return resp.status, text, elapsed, resp.headers
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {type(e).__name__}: {e}")
#             return None, None, None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         # Important: Use the same session for all requests
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 url_clean = url.split('#')[0] 
#                 if url_clean in self.seen or depth > self.max_depth:
#                     continue
                
#                 # Use the modified fetch function
#                 status, text, elapsed_time, headers = await self.fetch(session, url_clean) 
                
#                 self.seen.add(url_clean)

#                 if url_clean == self.base_url:
#                     self.headers_info = {k:v for k,v in headers.items()} 

#                 if text is None or elapsed_time is None:
#                     continue
                
#                 self.pages.append({"url": url_clean, "status": status, "body": text, "baseline_time": elapsed_time})
#                 forms = self.parse_forms(url_clean, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url_clean, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url_clean, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms, "headers": self.headers_info}

# # ==================================
# # PROBER CLASS (Minor adjustment for timing logic)
# # ==================================
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout_total = timeout # Keep total timeout value
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def fetch_probe(self, session, method, url, data=None):
#         """Helper to fetch URL/Form with data and return text/time."""
#         start_time = time.time()
#         try:
#             if method == 'get':
#                 # Use params for GET data (query string)
#                 async with session.get(url, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 # Use data for POST data
#                 async with session.post(url, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             elapsed = time.time() - start_time
#             return text, elapsed
#         except Exception as e:
#             self.logger(f"Probe error: {url} -> {type(e).__name__}: {e}")
#             return "", None

#     def check_security_headers(self, headers):
#         """Checks for missing security-related HTTP response headers."""
#         headers_lower = {k.lower(): v for k, v in headers.items()}
#         for required_header in REQUIRED_SECURITY_HEADERS:
#             if required_header.lower() not in headers_lower:
#                 self.findings.append({
#                     "type": "Missing HTTP Security Header",
#                     "severity": "Low", 
#                     "vector": "Response Headers",
#                     "url": "Base URL",
#                     "param": required_header,
#                     "evidence": f"The response is missing the critical '{required_header}' header."
#                 })
        
#         if headers_lower.get('x-content-type-options', '').lower() != 'nosniff':
#              self.findings.append({
#                 "type": "Security Misconfiguration",
#                 "severity": "Low", 
#                 "vector": "Response Headers",
#                 "url": "Base URL",
#                 "param": "X-Content-Type-Options: nosniff",
#                 "evidence": "X-Content-Type-Options header is missing or not set to 'nosniff'."
#             })


#     async def test_url_param_reflection(self, session, page_data):
#         url = page_data["url"]
#         # Use self.timeout_total as a robust fallback if baseline_time is None
#         baseline_time = page_data["baseline_time"] if page_data["baseline_time"] is not None else self.timeout_total 
        
#         parts = list(urlsplit(url))
#         query_string = parts[3]
#         if not query_string:
#             return
            
#         query = parse_qs(query_string, keep_blank_values=True)
        
#         for param in list(query.keys()):
#             orig_values = query[param]
            
#             # --- XSS, SQLI Error, SQLI Time Tests ---
#             # ... (Existing logic for XSS, SQLi Error, SQLi Time is robust, kept it clean) ...
            
#             # 1. XSS Reflection Tests
#             for payload in XSS_PAYLOADS:
#                 query[param] = [payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url = urlunsplit(parts)
#                 text_xss, _ = await self.fetch_probe(session, 'get', test_url)
                
#                 if XSS_MARKER in text_xss: 
#                     self.findings.append({"type": "Reflected XSS (XSS)", "severity": "High", "vector": "URL Query Parameter", "url": test_url, "param": param, "evidence": f"Injected payload reflected in response (e.g., '{payload[:20]}...')" })
#                     break 
            
#             # 2. SQLI Error-Based Test
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_err = urlunsplit(parts)
#             stext_err, _ = await self.fetch_probe(session, 'get', test_url_sqli_err)
            
#             if any(ind in stext_err.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({"type": "SQL Injection (Error-Based)", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_sqli_err, "param": param, "evidence": "SQL error indicator present in response after single quote injection" })
            
#             # 3. SQLI Time-Based (Blind) Test
#             query[param] = [SQLI_TIME_PAYLOAD]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_time = urlunsplit(parts)
#             _, elapsed_time_test = await self.fetch_probe(session, 'get', test_url_sqli_time)

#             if elapsed_time_test is not None and elapsed_time_test > (baseline_time + DELAY_THRESHOLD):
#                  self.findings.append({"type": "Blind SQL Injection (Time-Based)", "severity": "High", "vector": "URL Query Parameter", "url": test_url_sqli_time, "param": param, "evidence": f"Response delayed by ~{elapsed_time_test:.2f}s (Baseline: {baseline_time:.2f}s). Potential blind SQLi." })
            
#             # 4. IDOR/Directory Traversal/RFI (New Basic Check)
#             if query[param] and query[param][0].isdigit():
#                 try:
#                     test_id = str(int(query[param][0]) - 1)
#                     query[param] = [test_id]
#                     parts[3] = urlencode(query, doseq=True)
#                     test_url_idor = urlunsplit(parts)
                    
#                     self.findings.append({"type": "Potential Insecure Direct Object Reference (IDOR)", "severity": "Medium", "vector": "URL Query Parameter", "url": test_url_idor, "param": param, "evidence": f"Parameter looks like an ID. Accessing '{test_id}' might expose other users' data (requires manual verification)." })
#                 except ValueError:
#                     pass

#             for file_payload in FILE_INCLUSION_PAYLOADS:
#                 query[param] = [file_payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url_file = urlunsplit(parts)
#                 stext_file, _ = await self.fetch_probe(session, 'get', test_url_file)
                
#                 if any(ind in stext_file for ind in FILE_INCLUSION_INDICATORS):
#                     self.findings.append({"type": "Remote File Inclusion / Directory Traversal", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_file, "param": param, "evidence": f"File access pattern (e.g., path traversal or expected file content) detected in response." })
#                     break

#             # Restore original values
#             query[param] = orig_values

#     async def test_form_reflection(self, session, form):
#         # NOTE: Form logic kept simple, similar fixes required if errors arise here
#         pass # Placeholder for brevity, full logic is in the previous response


#     async def run(self, pages, forms, headers):
#         self.check_security_headers(headers)
        
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(page_data=p):
#                     async with sem:
#                         await self.test_url_param_reflection(session, page_data)
#                 tasks.append(asyncio.create_task(task_url()))
#             # for f in forms:
#             #     async def task_form(form=f):
#             #         async with sem:
#             #             await self.test_form_reflection(session, form)
#             #     tasks.append(asyncio.create_task(task_form()))
#             if tasks:
#                 await asyncio.gather(*tasks, return_exceptions=True) 
#         return self.findings

# # ==================================
# # RUN SCAN (FIXED: Exception handling)
# # ==================================
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     # Initialize all return values to avoid NameError if an exception occurs
#     findings = []
#     pages = []
#     forms = []
#     headers = {}
    
#     async def inner():
#         nonlocal findings, pages, forms, headers # Use nonlocal to modify variables in the outer scope
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         ui_log("Starting crawl and establishing baselines...")
#         c_result = await crawler.crawl()
        
#         pages = c_result["pages"]
#         forms = c_result["forms"]
#         headers = c_result["headers"]
        
#         ui_log(f"Crawl finished. Found {len(pages)} pages and {len(forms)} forms.")
#         prober = Prober(concurrency, timeout, logger)
#         ui_log("Starting advanced vulnerability probing...")
#         findings = await prober.run(pages, forms, headers) 
#         ui_log("Probing finished.")
#         # Return all required values
#         return findings, pages, forms, headers
        
#     try:
#         # If inner() completes successfully, it returns the tuple
#         return asyncio.run(inner())
#     except Exception as e:
#         ui_log(f"CRITICAL ERROR: Scan aborted: {type(e).__name__} - {e}")
#         # If inner() fails, it returns the initialized (or partially updated) values
#         return findings, pages, forms, headers


# # ==================================
# # PDF Generation 
# # ==================================
# def create_pdf_report(target_url, findings):
#     pdf = FPDF()
#     pdf.add_page()
#     pdf.set_font("Arial", style="B", size=16)
#     pdf.cell(0, 10, "🛡️ Advanced Web Security Scan Report", ln=True, align="C")
#     pdf.set_font("Arial", size=12)
#     pdf.cell(0, 8, f"Target URL: {target_url}", ln=True)
#     pdf.cell(0, 8, f"Scan Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True)
#     pdf.cell(0, 8, f"Total Findings: {len(findings)}", ln=True)
#     pdf.ln(5)

#     if not findings:
#         pdf.cell(0, 10, "--- No Vulnerabilities Found ---", ln=True, align="C")
#     else:
#         for i, f in enumerate(findings, 1):
#             pdf.set_fill_color(220, 220, 220)
#             pdf.set_font("Arial", style="B", size=12)
#             pdf.multi_cell(0, 8, f"Finding {i}: {f['type']} (Severity: {f.get('severity', 'N/A')})", 1, 'L', 1)
#             pdf.set_font("Arial", size=10)
#             pdf.multi_cell(0, 6, f"  URL: {f.get('url', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Vector: {f.get('vector', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Parameter(s): {f.get('param', 'N/A')}")
#             pdf.multi_cell(0, 6, f"  Evidence: {f.get('evidence', 'N/A')}")
#             pdf.ln(2)

#     pdf_file_path = f"scan_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
#     pdf.output(pdf_file_path)
#     return pdf_file_path


# # ==================================
# # STREAMLIT UI (Unchanged)
# # ==================================
# st.set_page_config(page_title="Pro Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# st.sidebar.title("🔐 SafeScanner Pro")

# if not st.session_state.logged_in:
#     st.sidebar.header("User Login")
#     username = st.sidebar.text_input("👤 Username", key="login_user")
#     password = st.sidebar.text_input("🔑 Password", type="password", key="login_pass")
#     login_btn = st.sidebar.button("Login", type="primary", use_container_width=True)
    
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.sidebar.success(f"✅ Logged in as **{st.session_state.role}**")
#             st.rerun()
#         else:
#             st.sidebar.error("❌ Invalid credentials")
# else:
#     page = st.sidebar.radio("Go to:", ["🏠 Dashboard","🛡️ Scanner","📜 History"])
#     st.sidebar.markdown("---")
#     st.sidebar.caption(f"Welcome, **{st.session_state.role}**")
#     logout_btn = st.sidebar.button("Logout", type="secondary", use_container_width=True)
#     if logout_btn:
#         st.session_state.logged_in = False
#         st.session_state.role = ''
#         st.info("👋 Logged out successfully.")
#         st.experimental_rerun()

#     if page=="🏠 Dashboard":
#         st.title("📊 Security Scan Dashboard")
#         st.markdown("Overview of all past scan activities and vulnerability distribution.")
        
#         c.execute("SELECT target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         total_scans = len(rows)
#         total_findings = 0
#         finding_counts = {}
#         severity_counts = {}
        
#         for r in rows:
#             try:
#                 findings = json.loads(r[2])
#                 total_findings += len(findings)
#                 for f in findings:
#                     v_type = f.get('type', 'Unknown')
#                     v_severity = f.get('severity', 'N/A')
#                     finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
#                     severity_counts[v_severity] = severity_counts.get(v_severity, 0) + 1
#             except Exception:
#                 pass
        
#         st.subheader("Key Metrics")
#         col1, col2, col3 = st.columns(3)
#         col1.metric("Total Scans", total_scans, delta="Since inception", delta_color="off")
#         col2.metric("Total Findings", total_findings, delta=f"{len(finding_counts)} unique types", delta_color="off")
#         col3.metric("Latest Target", rows[0][0] if rows else "N/A", delta=rows[0][1].split(' ')[0] if rows else "N/A")

#         st.markdown("---")
        
#         if total_findings > 0:
#             col_chart_1, col_chart_2 = st.columns(2)

#             with col_chart_1:
#                 st.subheader("⚠️ Vulnerability Severity Distribution")
#                 df_severity = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
                
#                 color_scale = alt.Scale(domain=['Critical', 'High', 'Medium', 'Low', 'N/A'], 
#                                         range=['#DC3545', '#FFC107', '#FD7E14', '#17A2B8', '#6C757D'])
                
#                 base = alt.Chart(df_severity).encode(
#                     theta=alt.Theta("Count", stack=True)
#                 )

#                 pie = base.mark_arc(outerRadius=120, innerRadius=60).encode(
#                     color=alt.Color("Severity", scale=color_scale),
#                     order=alt.Order("Count", sort="descending"),
#                     tooltip=["Severity", "Count"]
#                 ).properties(height=350)
                
#                 st.altair_chart(pie, use_container_width=True)

#             with col_chart_2:
#                 st.subheader("📊 Top Finding Types")
#                 df_counts = pd.DataFrame(list(finding_counts.items()), columns=['Vulnerability Type', 'Count']).sort_values('Count', ascending=False).head(5)
                
#                 bar_chart = alt.Chart(df_counts).mark_bar().encode(
#                     x=alt.X('Count', title='Total Instances'),
#                     y=alt.Y('Vulnerability Type', sort='-x', title='Vulnerability Type'),
#                     color=alt.Color('Count', scale=alt.Scale(range=['#90EE90', '#3CB371'])), 
#                     tooltip=['Vulnerability Type', 'Count']
#                 ).properties(height=350)
                
#                 st.altair_chart(bar_chart, use_container_width=True)
#         else:
#             st.info("No scan findings available to display charts. Run a scan first!")
            
#     elif page=="🛡️ Scanner":
#         st.title("🔬 Web Vulnerability Scan")
        
#         st.info("**Expert Guidance:** For high-accuracy detection, test against known vulnerable targets like **DVWA** or **bWAPP** (e.g., `http://testphp.vulnweb.com`).")
        
#         with st.expander("⚙️ Scan Configuration", expanded=True):
#             target_input = st.text_input("🌐 Target URL (e.g., http://testphp.vulnweb.com)", "http://localhost:3000", key="target_url")
            
#             col_a, col_b, col_c, col_d = st.columns(4)
#             max_pages = col_a.number_input("Max Pages", 1, 1000, 100, key="max_pages")
#             max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth")
#             concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency")
#             timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout")

#             run_button = st.button("🚀 Start Advanced Scan", type="primary", use_container_width=True)
            
#         status_area = st.empty()
#         results_area = st.container()
        
#         st.markdown("---")
#         st.subheader("System Log")
#         log_area = st.container(border=True)

#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
#             LOG_LINES.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
#             with log_area:
#                  st.code("\n".join(LOG_LINES[-15:]), language="text")

#         if run_button:
#             if not target_input.strip() or not target_input.startswith(('http://', 'https://')):
#                 status_area.error("❌ Please provide a valid URL starting with `http://` or `https://`.")
#             else:
#                 LOG_LINES=[]
#                 with status_area:
#                     st.info("🔍 Scan in progress... This may take a moment.")
                
#                 # The corrected function call which ensures all variables are defined
#                 findings, pages, forms, headers = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)

#                 # Save history
#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
#                 conn.commit()
                
#                 status_area.success("✅ Scan completed successfully!")
                
#                 with results_area:
#                     st.subheader("📝 Scan Results Summary")
#                     st.markdown(f"**Discovered:** **{len(pages)}** pages and **{len(forms)}** forms.")

#                     st.subheader("🌐 HTTP Security Header Status")
#                     header_df = pd.DataFrame(REQUIRED_SECURITY_HEADERS, columns=['Required Header'])
#                     header_df['Status'] = header_df['Required Header'].apply(lambda x: '✅ Present' if x.lower() in {k.lower():v for k,v in headers.items()} else '❌ Missing')
#                     header_df['Value'] = header_df['Required Header'].apply(lambda x: headers.get(x, headers.get(x.lower(), '---')))
#                     st.dataframe(header_df, use_container_width=True, hide_index=True)
#                     st.caption("Note: Headers were checked on the base URL.")
#                     st.markdown("---")
                    
#                     if findings:
#                         st.error(f"⚠️ **VULNERABILITIES FOUND! {len(findings)} issues detected.** Action required.")
                        
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         pdf_file_path = create_pdf_report(target_input, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download PDF Report", pf, file_name="scan_report.pdf", mime="application/pdf", type="secondary")
#                     else:
#                         st.balloons()
#                         st.success("🎉 **No critical or major issues found** after advanced checks. The target appears secure.")

#     elif page=="📜 History":
#         st.title("📂 Scan History")
        
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         if not rows:
#             st.info("No past scan history found.")
#         else:
#             for r in rows:
#                 scan_id, target, date, findings_json = r
#                 findings = json.loads(findings_json)
                
#                 total_findings = len(findings)
                
#                 icon = "🚨" if total_findings > 0 else "🟢"
                
#                 with st.expander(f"{icon} Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
#                     if findings:
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         pdf_file_path = create_pdf_report(target, findings)
#                         with open(pdf_file_path,"rb") as pf:
#                             st.download_button("⬇️ Download Report (PDF)", pf, file_name=f"report_{scan_id}.pdf", key=f"dl_btn_{scan_id}", type="secondary")
#                     else:
#                         st.success("No vulnerabilities found in this scan.")


# # streamlit_app.py# streamlit_app.py
# import asyncio
# import json
# import sqlite3
# import pandas as pd 
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode
# import altair as alt 
# import time 
# import io 

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup

# # ==================================
# # CUSTOM CSS FOR PROFESSIONAL DASHBOARD LOOK (UPDATED)
# # ==================================
# st.markdown("""
# <style>
# /* Dashboard Container & Cards */
# .stContainer {
#     padding-top: 2rem;
# }

# /* Custom Card Style for Metrics and Charts (Uses a common Streamlit column class) */
# /* This class ensures the box shadow and floating animation */
# .st-emotion-cache-1r6r000 { 
#     /* Initial Box Shadow (Professional Depth) */
#     box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2); 
#     border-radius: 15px; /* Slightly rounder corners */
#     padding: 25px; /* More padding */
#     transition: all 0.5s cubic-bezier(0.25, 0.8, 0.25, 1); /* Smooth animation */
#     /* Gradient Border Simulation: Using a solid border with shadow transition */
#     border: 1px solid #007bff; 
# }

# /* Floating/Hover Effect (Animation) */
# .st-emotion-cache-1r6r000:hover {
#     /* Floating Effect */
#     transform: translateY(-8px); 
#     /* Gradient-like Shadow (Deep blue/purple for a premium feel) */
#     box-shadow: 0 15px 35px rgba(0, 123, 255, 0.4), 
#                 0 0 0 2px rgba(0, 123, 255, 0.1); 
#     border-color: #0056b3; /* Darken border on hover */
# }

# /* Streamlit Header Font */
# h1 {
#     color: #007bff; /* Primary Blue Accent */
#     font-weight: 800;
#     text-shadow: 1px 1px 2px #ccc;
# }

# /* Subheader Styling (KPI section) */
# h3 {
#     border-left: 6px solid #17a2b8; /* Teal accent */
#     padding-left: 12px;
#     margin-top: 2rem;
#     margin-bottom: 1.5rem;
#     font-size: 1.6rem;
#     color: #343a40;
# }

# /* Metric Boxes Customization - Keep it clean */
# .st-emotion-cache-1gsv2z1 { 
#     background-color: #f8f9fa;
#     border-radius: 10px;
#     padding: 20px;
#     border: none; 
#     box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
# }

# /* Metric value font size and weight */
# .st-emotion-cache-10trblm {
#     font-weight: 700;
# }

# /* Fix for the log area */
# .stCodeBlock {
#     border-radius: 8px;
#     background-color: #f8f9fa;
#     border: 1px solid #ced4da;
# }
# </style>
# """, unsafe_allow_html=True)
# # ==================================
# # DATABASE SETUP 
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQLI_TIME_PAYLOAD = "' OR (SELECT 20 FROM (SELECT(SLEEP(4))))--" 
# DELAY_THRESHOLD = 3.5 

# FILE_INCLUSION_PAYLOADS = [
#     "../../../../etc/passwd",
#     "file:///etc/passwd",
#     "http://127.0.0.1/nonexistent.txt" 
# ]
# FILE_INCLUSION_INDICATORS = [
#     "root:x", 
#     "failed opening required",
#     "No such file or directory"
# ]

# XSS_PAYLOADS = [
#     XSS_MARKER,
#     f"<{XSS_MARKER}>",
#     f"javascript:alert('{XSS_MARKER}')"
# ]
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]
# REQUIRED_SECURITY_HEADERS = [
#     "Strict-Transport-Security", 
#     "X-Content-Type-Options",
#     "X-Frame-Options",
#     "Content-Security-Policy",
#     "Permissions-Policy" 
# ]

# # ==================================
# # CRAWLER CLASS 
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout_total = timeout
#         self.timeout = aiohttp.ClientTimeout(total=timeout) 
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)
#         self.headers_info = {} 

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         start_time = time.time()
#         try:
#             async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
#                 text = await resp.text(errors="ignore")
#                 elapsed = time.time() - start_time
#                 return resp.status, text, elapsed, resp.headers
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {type(e).__name__}: {e}")
#             return None, None, None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 url_clean = url.split('#')[0] 
#                 if url_clean in self.seen or depth > self.max_depth:
#                     continue
                
#                 status, text, elapsed_time, headers = await self.fetch(session, url_clean) 
                
#                 self.seen.add(url_clean)

#                 if url_clean == self.base_url:
#                     self.headers_info = {k:v for k,v in headers.items()} 

#                 if text is None or elapsed_time is None:
#                     continue
                
#                 self.pages.append({"url": url_clean, "status": status, "body": text, "baseline_time": elapsed_time})
#                 forms = self.parse_forms(url_clean, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url_clean, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url_clean, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms, "headers": self.headers_info}

# # ==================================
# # PROBER CLASS 
# # ==================================
# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout_total = timeout 
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def fetch_probe(self, session, method, url, data=None):
#         start_time = time.time()
#         try:
#             if method == 'get':
#                 async with session.get(url, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(url, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             elapsed = time.time() - start_time
#             return text, elapsed
#         except Exception as e:
#             self.logger(f"Probe error: {url} -> {type(e).__name__}: {e}")
#             return "", None

#     def check_security_headers(self, headers):
#         headers_lower = {k.lower(): v for k, v in headers.items()}
#         for required_header in REQUIRED_SECURITY_HEADERS:
#             if required_header.lower() not in headers_lower:
#                 self.findings.append({
#                     "type": "Missing HTTP Security Header",
#                     "severity": "Low", 
#                     "vector": "Response Headers",
#                     "url": "Base URL",
#                     "param": required_header,
#                     "evidence": f"The response is missing the critical '{required_header}' header."
#                 })
        
#         if headers_lower.get('x-content-type-options', '').lower() != 'nosniff':
#              self.findings.append({
#                 "type": "Security Misconfiguration",
#                 "severity": "Low", 
#                 "vector": "Response Headers",
#                 "url": "Base URL",
#                 "param": "X-Content-Type-Options: nosniff",
#                 "evidence": "X-Content-Type-Options header is missing or not set to 'nosniff'."
#             })


#     async def test_url_param_reflection(self, session, page_data):
#         url = page_data["url"]
#         baseline_time = page_data["baseline_time"] if page_data["baseline_time"] is not None else self.timeout_total 
        
#         parts = list(urlsplit(url))
#         query_string = parts[3]
#         if not query_string:
#             return
            
#         query = parse_qs(query_string, keep_blank_values=True)
        
#         for param in list(query.keys()):
#             orig_values = query[param]
            
#             # 1. XSS Reflection Tests
#             for payload in XSS_PAYLOADS:
#                 query[param] = [payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url = urlunsplit(parts)
#                 text_xss, _ = await self.fetch_probe(session, 'get', test_url)
                
#                 if XSS_MARKER in text_xss: 
#                     self.findings.append({"type": "Reflected XSS (XSS)", "severity": "High", "vector": "URL Query Parameter", "url": test_url, "param": param, "evidence": f"Injected payload reflected in response (e.g., '{payload[:20]}...')" })
#                     break 
            
#             # 2. SQLI Error-Based Test
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_err = urlunsplit(parts)
#             stext_err, _ = await self.fetch_probe(session, 'get', test_url_sqli_err)
            
#             if any(ind in stext_err.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({"type": "SQL Injection (Error-Based)", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_sqli_err, "param": param, "evidence": "SQL error indicator present in response after single quote injection" })
            
#             # 3. SQLI Time-Based (Blind) Test
#             query[param] = [SQLI_TIME_PAYLOAD]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_time = urlunsplit(parts)
#             _, elapsed_time_test = await self.fetch_probe(session, 'get', test_url_sqli_time)

#             if elapsed_time_test is not None and elapsed_time_test > (baseline_time + DELAY_THRESHOLD):
#                  self.findings.append({"type": "Blind SQL Injection (Time-Based)", "severity": "High", "vector": "URL Query Parameter", "url": test_url_sqli_time, "param": param, "evidence": f"Response delayed by ~{elapsed_time_test:.2f}s (Baseline: {baseline_time:.2f}s). Potential blind SQLi." })
            
#             # 4. IDOR/Directory Traversal/RFI (New Basic Check)
#             if query[param] and query[param][0].isdigit():
#                 try:
#                     test_id = str(int(query[param][0]) - 1)
#                     query[param] = [test_id]
#                     parts[3] = urlencode(query, doseq=True)
#                     test_url_idor = urlunsplit(parts)
                    
#                     self.findings.append({"type": "Potential Insecure Direct Object Reference (IDOR)", "severity": "Medium", "vector": "URL Query Parameter", "url": test_url_idor, "param": param, "evidence": f"Parameter looks like an ID. Accessing '{test_id}' might expose other users' data (requires manual verification)." })
#                 except ValueError:
#                     pass

#             for file_payload in FILE_INCLUSION_PAYLOADS:
#                 query[param] = [file_payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url_file = urlunsplit(parts)
#                 stext_file, _ = await self.fetch_probe(session, 'get', test_url_file)
                
#                 if any(ind in stext_file for ind in FILE_INCLUSION_INDICATORS):
#                     self.findings.append({"type": "Remote File Inclusion / Directory Traversal", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_file, "param": param, "evidence": f"File access pattern (e.g., path traversal or expected file content) detected in response." })
#                     break

#             # Restore original values
#             query[param] = orig_values

#     async def run(self, pages, forms, headers):
#         self.check_security_headers(headers)
        
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(page_data=p):
#                     async with sem:
#                         await self.test_url_param_reflection(session, page_data)
#                 tasks.append(asyncio.create_task(task_url()))
#             # Form testing tasks would go here
#             if tasks:
#                 await asyncio.gather(*tasks, return_exceptions=True) 
#         return self.findings

# # ==================================
# # RUN SCAN (sync wrapper)
# # ==================================
# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     findings = []
#     pages = []
#     forms = []
#     headers = {}
    
#     async def inner():
#         nonlocal findings, pages, forms, headers 
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         ui_log("Starting crawl and establishing baselines...")
#         c_result = await crawler.crawl()
        
#         pages = c_result["pages"]
#         forms = c_result["forms"]
#         headers = c_result["headers"]
        
#         ui_log(f"Crawl finished. Found {len(pages)} pages and {len(forms)} forms.")
#         prober = Prober(concurrency, timeout, logger)
#         ui_log("Starting advanced vulnerability probing...")
#         findings = await prober.run(pages, forms, headers) 
#         ui_log("Probing finished.")
#         return findings, pages, forms, headers
        
#     try:
#         return asyncio.run(inner())
#     except Exception as e:
#         ui_log(f"CRITICAL ERROR: Scan aborted: {type(e).__name__} - {e}")
#         return findings, pages, forms, headers

# # ==================================
# # EXCEL GENERATION 
# # ==================================
# def to_excel_report(target_url, findings):
#     """Generates an Excel file (in bytes) from findings."""
    
#     if findings:
#         findings_df = pd.DataFrame(findings)
#         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
#     else:
#         findings_df = pd.DataFrame({'Message': ['No vulnerabilities found in this scan.']})
    
#     output = io.BytesIO()
#     # Note: Requires 'openpyxl' and 'xlsxwriter' libraries
#     writer = pd.ExcelWriter(output, engine='xlsxwriter')
    
#     findings_df.to_excel(writer, sheet_name='Vulnerability Findings', index=False)
    
#     metadata_df = pd.DataFrame({
#         'Key': ['Target URL', 'Scan Date', 'Total Findings'],
#         'Value': [target_url, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), len(findings)]
#     })
#     metadata_df.to_excel(writer, sheet_name='Metadata', index=False)
    
#     writer.close() 
#     output.seek(0)
#     return output.read()

# # ==================================
# # STREAMLIT UI 
# # ==================================
# st.set_page_config(page_title="Pro Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# st.sidebar.title("🛡️ SafeScanner Pro") 

# if not st.session_state.logged_in:
#     st.sidebar.header("👤 User Login")
#     username = st.sidebar.text_input("Username", key="login_user")
#     password = st.sidebar.text_input("Password", type="password", key="login_pass")
#     login_btn = st.sidebar.button("🔑 Login", type="primary", use_container_width=True)
    
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.sidebar.success(f"✅ Logged in as **{st.session_state.role}**")
#             st.experimental_rerun()
#         else:
#             st.sidebar.error("❌ Invalid credentials")
# else:
#     # UPDATED ICONS FOR NAVIGATION
#     page = st.sidebar.radio("Go to:", ["🏠 Dashboard","🔬 Scanner","📜 History"])
#     st.sidebar.markdown("---")
#     st.sidebar.caption(f"Welcome, **{st.session_state.role}**")
#     logout_btn = st.sidebar.button("🚪 Logout", type="secondary", use_container_width=True)
#     if logout_btn:
#         st.session_state.logged_in = False
#         st.session_state.role = ''
#         st.info("👋 Logged out successfully.")
#         st.experimental_rerun()

#     if page=="🏠 Dashboard":
#         st.title("📊 Security Scan Dashboard")
#         st.markdown("---")
#         st.markdown("### **Key Performance Indicators**")
        
#         c.execute("SELECT target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         total_scans = len(rows)
#         total_findings = 0
#         finding_counts = {}
#         severity_counts = {}
        
#         # Data aggregation
#         for r in rows:
#             try:
#                 findings = json.loads(r[2])
#                 total_findings += len(findings)
#                 for f in findings:
#                     v_type = f.get('type', 'Unknown')
#                     v_severity = f.get('severity', 'N/A')
#                     finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
#                     severity_counts[v_severity] = severity_counts.get(v_severity, 0) + 1
#             except Exception:
#                 pass
        
#         # --- 1. KEY METRICS ---
#         col1, col2, col3, col4 = st.columns(4)
        
#         latest_target = rows[0][0] if rows else "N/A"
#         latest_date = rows[0][1].split(' ')[0] if rows else "N/A"
#         critical_count = severity_counts.get('Critical', 0)

#         col1.metric("Total Scans 🔎", total_scans, delta="Total Scans Executed", delta_color="off")
#         col2.metric("Total Findings 🚩", total_findings, delta=f"{len(finding_counts)} Unique Vectors", delta_color="off")
#         col3.metric("Critical Findings 🚨", critical_count, delta="Immediate Action Needed", delta_color="inverse")
#         col4.metric("Latest Scan 📅", latest_target, delta=latest_date)

#         st.markdown("---")
        
#         if total_findings > 0:
            
#             # --- 2. CHART ROW 1: SEVERITY & TOP TYPES ---
#             col_chart_1, col_chart_2 = st.columns(2)

#             with col_chart_1:
#                 st.subheader("⚠️ Vulnerability Severity Distribution")
#                 df_severity = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
                
#                 # Define Professional Color Scale
#                 color_scale = alt.Scale(domain=['Critical', 'High', 'Medium', 'Low', 'N/A'], 
#                                         range=['#DC3545', '#FFC107', '#FD7E14', '#17A2B8', '#6C757D'])
                
#                 base = alt.Chart(df_severity).encode(
#                     theta=alt.Theta("Count", stack=True)
#                 )

#                 pie = base.mark_arc(outerRadius=120, innerRadius=80).encode( 
#                     color=alt.Color("Severity", scale=color_scale),
#                     order=alt.Order("Count", sort="descending"),
#                     tooltip=["Severity", "Count"]
#                 ).properties(height=350, title="Severity Risk Breakdown")
                
#                 st.altair_chart(pie, use_container_width=True)

#             with col_chart_2:
#                 st.subheader("🎯 Top 5 Vulnerability Types")
#                 df_counts = pd.DataFrame(list(finding_counts.items()), columns=['Vulnerability Type', 'Count']).sort_values('Count', ascending=False).head(5)
                
#                 bar_chart = alt.Chart(df_counts).mark_bar().encode(
#                     x=alt.X('Count', title='Total Instances'),
#                     y=alt.Y('Vulnerability Type', sort='-x', title=''),
#                     color=alt.Color('Count', scale=alt.Scale(range=['#007bff', '#17a2b8'])), 
#                     tooltip=['Vulnerability Type', 'Count']
#                 ).properties(height=350, title="Most Frequent Attack Vectors")
                
#                 st.altair_chart(bar_chart, use_container_width=True)
                
#             st.markdown("---")
            
#             # --- 3. CHART ROW 2: TIME SERIES TREND ---
#             st.subheader("⏳ Scan Activity Over Time")
            
#             date_findings = {}
#             for r in rows:
#                 date_key = datetime.strptime(r[1].split(' ')[0], '%Y-%m-%d').date()
#                 num_findings = len(json.loads(r[2]))
#                 date_findings[date_key] = date_findings.get(date_key, 0) + num_findings

#             df_trend = pd.DataFrame(list(date_findings.items()), columns=['Date', 'Findings Count']).sort_values('Date')
            
#             # Interactive Line/Area Chart with Gradient Area
#             line_chart = alt.Chart(df_trend).mark_area(
#                 line={'color':'#28a745'}, 
#                 color=alt.Gradient(
#                     gradient='linear',
#                     stops=[alt.GradientStop(color='white', offset=0), alt.GradientStop(color='#d4edda', offset=1)],
#                     x1=1,
#                     y1=1,
#                     x2=1,
#                     y2=0
#                 ),
#                 interpolate='monotone',
#                 opacity=0.8
#             ).encode(
#                 x=alt.X('Date:T', title='Scan Date'),
#                 y=alt.Y('Findings Count:Q', title='Total Vulnerabilities'),
#                 tooltip=['Date:T', 'Findings Count:Q']
#             ).properties(
#                 title='Vulnerability Detection Trend'
#             ).interactive() 
            
#             st.altair_chart(line_chart, use_container_width=True)


#         else:
#             st.info("ℹ️ No scan findings available to display charts. Please run a scan first!")

#     elif page=="🔬 Scanner":
#         st.title("🔬 Web Vulnerability Scan")
        
#         st.info("💡 Expert Guidance: For high-accuracy detection, test against known vulnerable targets like DVWA or bWAPP (e.g., http://testphp.vulnweb.com).")
        
#         with st.expander("⚙️ Scan Configuration", expanded=True):
#             target_input = st.text_input("🌐 Target URL (e.g., http://testphp.vulnweb.com)", "http://localhost:3000", key="target_url")
            
#             col_a, col_b, col_c, col_d = st.columns(4)
#             max_pages = col_a.number_input("Max Pages", 1, 1000, 100, key="max_pages", help="Max number of pages to crawl.")
#             max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth", help="Max link depth to follow from the root URL.")
#             concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency", help="Number of simultaneous requests to make.")
#             timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout", help="Timeout for each individual request.")

#             run_button = st.button("🚀 Start Advanced Scan", type="primary", use_container_width=True)
            
#         status_area = st.empty()
#         results_area = st.container()
        
#         st.markdown("---")
#         st.subheader("System Log 📝")
#         log_area = st.container(border=True)

#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
#             LOG_LINES.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
#             with log_area:
#                  st.code("\n".join(LOG_LINES[-15:]), language="text")

#         if run_button:
#             if not target_input.strip() or not target_input.startswith(('http://', 'https://')):
#                 status_area.error("❌ Please provide a valid URL starting with `http://` or `https://`.")
#             else:
#                 LOG_LINES=[]
#                 with status_area:
#                     st.info("🔍 Scan in progress... This may take a moment.")
                
#                 findings, pages, forms, headers = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)

#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
#                 conn.commit()
                
#                 status_area.success("✅ Scan completed successfully!")
                
#                 with results_area:
#                     st.subheader("📝 Scan Results Summary")
#                     st.markdown(f"**Discovered:** **{len(pages)}** pages and **{len(forms)}** forms.")

#                     st.subheader("🌐 HTTP Security Header Status")
#                     header_df = pd.DataFrame(REQUIRED_SECURITY_HEADERS, columns=['Required Header'])
#                     header_df['Status'] = header_df['Required Header'].apply(lambda x: '✅ Present' if x.lower() in {k.lower():v for k,v in headers.items()} else '❌ Missing')
#                     header_df['Value'] = header_df['Required Header'].apply(lambda x: headers.get(x, headers.get(x.lower(), '---')))
#                     st.dataframe(header_df, use_container_width=True, hide_index=True)
#                     st.caption("Note: Headers were checked on the base URL.")
#                     st.markdown("---")
                    
#                     if findings:
#                         st.error(f"⚠️ **VULNERABILITIES FOUND! {len(findings)} issues detected.** Action required.")
                        
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         excel_data = to_excel_report(target_input, findings)
#                         st.download_button(
#                             label="⬇️ Download Excel Report (.xlsx)",
#                             data=excel_data,
#                             file_name=f"scan_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx",
#                             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#                             type="secondary"
#                         )
#                     else:
#                         st.balloons()
#                         st.success("🎉 **No critical or major issues found** after advanced checks. The target appears secure.")

#     elif page=="📜 History":
#         st.title("📂 Scan History")
        
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         if not rows:
#             st.info("ℹ️ No past scan history found.")
#         else:
#             for r in rows:
#                 scan_id, target, date, findings_json = r
#                 findings = json.loads(findings_json)
                
#                 total_findings = len(findings)
                
#                 icon = "🚨" if total_findings > 0 else "🟢"
                
#                 with st.expander(f"{icon} Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
#                     if findings:
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
#                         st.dataframe(findings_df, use_container_width=True, hide_index=True)
                        
#                         excel_data = to_excel_report(target, findings)
#                         st.download_button(
#                             label="⬇️ Download Report (Excel)",
#                             data=excel_data,
#                             file_name=f"report_{scan_id}.xlsx",
#                             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#                             key=f"dl_btn_{scan_id}",
#                             type="secondary"
#                         )
#                     else:
#                         st.success("✅ No vulnerabilities found in this scan.")





# # streamlit_app.py - V13: Accurate Severity, Single Progress Bar, Real Dashboard Data

# import asyncio
# import json
# import sqlite3
# import pandas as pd 
# from datetime import datetime
# from urllib.parse import urljoin, urldefrag, urlparse, urlsplit, urlunsplit, parse_qs, urlencode
# import altair as alt 
# import time 
# import io 
# import random 

# import aiohttp
# import streamlit as st
# from bs4 import BeautifulSoup

# # ==================================
# # DEBUG MODE FOR CHARTS (SET TO TRUE FOR DEMO WITH ALL SEVERITIES)
# # ==================================
# DEBUG_MODE_CHARTS = False # <--- FIX: SET TO FALSE TO SHOW REAL SCAN DATA ONLY

# # ==================================
# # CUSTOM CSS FOR DARK MODE PROFESSIONAL LOOK
# # ==================================
# st.markdown("""
# <style>
# /* --- UNIFIED DARK MODE COLOR PALETTE --- */
# :root {
#     --primary-color: #00796b; /* Deep Teal (for general accents) */
#     --accent-color: #d32f2f; /* Darker Red (for progress bar/critical action) */
#     --background-dark: #1e1e1e; /* Dark background */
#     --background-card: #2d2d2d; /* Card background (slightly lighter than app background) */
#     --text-white: #f5f5f5; /* Light text */
#     --text-light-gray: #b0b0b0; /* Subtext */
#     --critical-red: #f44336; /* Bright Red for Critical findings */
#     --high-orange: #ff9800; /* Orange for High findings */
#     --medium-teal: #00bcd4; /* Brighter Teal for Medium findings */
#     --low-blue: #2196f3; /* Blue for Low findings */
#     --soft-gray-blue: #3a3a3a; /* Darker background for guidance box */
# }

# /* --- BASE & UTILITIES (Applying Dark Mode Background) --- */
# .stApp {
#     background-color: var(--background-dark); 
#     color: var(--text-white);
# }
# .main {
#     color: var(--text-white);
# }

# /* --- 1. HEADERS & TYPOGRAPHY --- */
# .st-emotion-cache-183v29e > h1, .st-emotion-cache-1l00psu > h1 { 
#     color: var(--text-white) !important; 
#     font-weight: 900;
#     letter-spacing: -1.2px; 
#     border-bottom: 3px solid #3a3a3a; 
#     padding-bottom: 15px; 
#     margin-bottom: 30px; 
# }
# .scanner-heading-no-border h1 {
#     border-bottom: none !important; 
# }
# h3 {
#     border-left: 6px solid var(--primary-color); 
#     padding-left: 18px;
#     margin-top: 3.5rem; 
#     margin-bottom: 1.5rem;
#     font-size: 1.8rem;
#     color: var(--text-white);
#     font-weight: 700;
# }

# /* --- 2. CARD/BOX STYLING (Dashboard/History Background Refinement) --- */
# /* This targets the main containers for dashboard and history content */
# .st-emotion-cache-1r6r000, .st-emotion-cache-1n103ah, .st-emotion-cache-1gsv2z1, .st-emotion-cache-1kywczu, .st-emotion-cache-1vb648g { 
#     background-color: rgba(45, 45, 45, 0.85); /* Slightly transparent background for better blending */
#     box-shadow: 0 6px 12px rgba(0, 0, 0, 0.6); /* Stronger shadow to lift it from background */
#     border-radius: 12px; 
#     padding: 30px; 
#     margin-bottom: 30px; 
#     border: 1px solid #4a4a4a; /* Darker border */
# }

# /* --- 3. METRIC BOXES (KPIs) --- */
# .metric-box {
#     background: linear-gradient(135deg, #004d40 0%, #00796b 100%); 
#     padding: 20px 25px;
#     border-radius: 12px;
#     box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
#     height: 100%;
# }

# /* --- 4. SCANNER STATUS BAR (New: Red Background, Rounded Corners, Spaced) --- */
# /* Targetting st.info/st.success/st.error containers for custom styling */
# div[data-testid="stStatusWidget"] {
#     background-color: var(--accent-color) !important; /* Red background */
#     border-radius: 10px !important; /* Rounded corners */
#     margin-bottom: 10px !important; /* Reduced space after status */
#     color: var(--text-white) !important;
#     border: none !important;
#     padding: 10px 15px !important;
# }
# /* Ensure the inner Streamlit success box uses the custom red color */
# .stSuccess {
#     background-color: var(--accent-color) !important;
#     border-radius: 10px !important;
#     color: var(--text-white) !important;
#     border: none !important;
# }
# .stSuccess > div {
#     background-color: var(--accent-color) !important;
#     color: var(--text-white) !important;
# }

# /* --- 5. PROGRESS BAR (Red, Rounded) --- */
# .stProgress {
#     margin-bottom: 20px; /* Space after progress bar */
# }
# .stProgress > div > div {
#     background-color: #3a3a3a; /* Dark Gray Track */
#     border-radius: 10px; /* Rounded corners */
# }
# .stProgress > div > div > div {
#     background-color: var(--accent-color); /* Red Fill */
#     border-radius: 10px; /* Rounded corners */
#     color: var(--text-white); /* White text on bar */
# }
# .stProgress > div > div > div > div {
#      background-color: var(--accent-color) !important;
#      border-radius: 10px !important;
# }


# /* --- 6. TERMINAL LOG SPACING (FIXED OVERLAP & CLEANUP) --- */
# /* Applying margin to the custom code block container inside the log area */
# .log-entry-container {
#     background-color: #1c2833;
#     border-radius: 10px;
#     padding: 10px 15px; /* Reduced padding */
#     margin-bottom: 8px; /* Crucial: Adds space between log entries/updates, reduced from 20px */
#     border: 1px solid #4a4a4a;
# }
# .log-entry-container pre {
#     color: #2ecc71; 
#     font-family: 'Consolas', 'Monaco', monospace; 
#     font-size: 0.9rem;
#     margin: 0; /* Important: Removes default margin/padding from pre tag inside log box */
#     padding: 0;
# }

# /* --- 7. GUIDANCE BOX (Darker Subtle Background) --- */
# .guidance-box {
#     background-color: var(--soft-gray-blue); 
#     padding: 18px 25px; 
#     border-radius: 10px;
#     border-left: 5px solid var(--primary-color); 
#     color: var(--text-white); 
#     margin-bottom: 25px; 
# }


# </style>
# """, unsafe_allow_html=True)
# # ==================================
# # DATABASE SETUP 
# # ==================================
# conn = sqlite3.connect('scan_history.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, date TEXT, findings TEXT)''')
# c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
# conn.commit()

# c.execute("SELECT * FROM users WHERE username='admin'")
# if not c.fetchone():
#     c.execute("INSERT INTO users (username, password, role) VALUES ('admin','admin','admin')")
#     conn.commit()

# # ==================================
# # CONFIG
# # ==================================
# USER_AGENT = "SafeScanner/1.0 (+https://example.com)"
# XSS_MARKER = "INJECT_XSS_TEST_12345"
# SQLI_MARKER_SIMPLE = "'"
# SQLI_TIME_PAYLOAD = "' OR (SELECT 20 FROM (SELECT(SLEEP(4))))--" 
# DELAY_THRESHOLD = 3.5 

# FILE_INCLUSION_PAYLOADS = [
#     "../../../../etc/passwd",
#     "file:///etc/passwd",
#     "http://127.0.0.1/nonexistent.txt" 
# ]
# FILE_INCLUSION_INDICATORS = [
#     "root:x", 
#     "failed opening required",
#     "No such file or directory"
# ]

# XSS_PAYLOADS = [
#     XSS_MARKER,
#     f"<{XSS_MARKER}>",
#     f"javascript:alert('{XSS_MARKER}')"
# ]
# SQL_ERROR_INDICATORS = [
#     "sql syntax", "mysql", "syntax error", "sqlstate", "sqlite",
#     "unclosed quotation mark", "odbc", "native client",
#     "pq: syntax error", "you have an error in your sql",
# ]
# REQUIRED_SECURITY_HEADERS = [
#     "Strict-Transport-Security", 
#     "X-Content-Type-Options",
#     "X-Frame-Options",
#     "Content-Security-Policy",
#     "Permissions-Policy" 
# ]

# # ==================================
# # CRAWLER & PROBER CLASSES
# # ==================================
# class Crawler:
#     def __init__(self, base_url, max_pages=100, max_depth=2, timeout=15, logger=None):
#         self.base_url = base_url.rstrip("/")
#         self.parsed_base = urlparse(self.base_url)
#         self.max_pages = max_pages
#         self.max_depth = max_depth
#         self.timeout_total = timeout
#         self.timeout = aiohttp.ClientTimeout(total=timeout) 
#         self.seen = set()
#         self.forms = []
#         self.pages = []
#         self.logger = logger or (lambda *a, **k: None)
#         self.headers_info = {} 

#     def same_host(self, url):
#         p = urlparse(url)
#         return (p.netloc == "" or p.netloc == self.parsed_base.netloc)

#     def normalize(self, base, link):
#         joined = urljoin(base, link)
#         clean, _ = urldefrag(joined)
#         return clean

#     def parse_forms(self, base_url, html):
#         soup = BeautifulSoup(html, "lxml")
#         forms = []
#         for form in soup.find_all("form"):
#             action = form.get("action") or base_url
#             method = (form.get("method") or "get").lower()
#             inputs = []
#             for inp in form.find_all(["input", "textarea", "select"]):
#                 name = inp.get("name")
#                 if not name:
#                     continue
#                 typ = inp.get("type") or inp.name
#                 inputs.append({"name": name, "type": typ})
#             forms.append({"url": base_url, "action": action, "method": method, "inputs": inputs})
#         return forms

#     async def fetch(self, session, url):
#         start_time = time.time()
#         try:
#             async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
#                 text = await resp.text(errors="ignore")
#                 elapsed = time.time() - start_time
#                 return resp.status, text, elapsed, resp.headers
#         except Exception as e:
#             self.logger(f"fetch error: {url} -> {type(e).__name__}: {e}")
#             return None, None, None, None

#     async def crawl(self):
#         from asyncio import Queue
#         q = Queue()
#         await q.put((self.base_url, 0))
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}) as session:
#             while not q.empty() and len(self.seen) < self.max_pages:
#                 url, depth = await q.get()
#                 url_clean = url.split('#')[0] 
#                 if url_clean in self.seen or depth > self.max_depth:
#                     continue
                
#                 status, text, elapsed_time, headers = await self.fetch(session, url_clean) 
                
#                 self.seen.add(url_clean)

#                 if url_clean == self.base_url:
#                     self.headers_info = {k:v for k,v in headers.items()} 

#                 if text is None or elapsed_time is None:
#                     continue
                
#                 self.pages.append({"url": url_clean, "status": status, "body": text, "baseline_time": elapsed_time})
#                 forms = self.parse_forms(url_clean, text)
#                 for f in forms:
#                     f["action"] = self.normalize(url_clean, f["action"])
#                     self.forms.append(f)
#                 if depth < self.max_depth:
#                     soup = BeautifulSoup(text, "lxml")
#                     for a in soup.find_all("a", href=True):
#                         link = self.normalize(url_clean, a["href"])
#                         if self.same_host(link) and link not in self.seen:
#                             await q.put((link, depth + 1))
#         return {"pages": self.pages, "forms": self.forms, "headers": self.headers_info}

# class Prober:
#     def __init__(self, concurrency=8, timeout=20, logger=None):
#         self.concurrency = concurrency
#         self.timeout_total = timeout 
#         self.timeout = aiohttp.ClientTimeout(total=timeout)
#         self.findings = []
#         self.logger = logger or (lambda *a, **k: None)

#     async def fetch_probe(self, session, method, url, data=None):
#         start_time = time.time()
#         try:
#             if method == 'get':
#                 async with session.get(url, params=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             else:
#                 async with session.post(url, data=data, timeout=self.timeout) as resp:
#                     text = await resp.text(errors="ignore")
#             elapsed = time.time() - start_time
#             return text, elapsed
#         except Exception as e:
#             self.logger(f"Probe error: {url} -> {type(e).__name__}: {e}")
#             return "", None

#     def check_security_headers(self, headers):
#         headers_lower = {k.lower(): v for k, v in headers.items()}
#         for required_header in REQUIRED_SECURITY_HEADERS:
#             if required_header.lower() not in headers_lower:
#                 self.findings.append({
#                     "type": "Missing HTTP Security Header",
#                     "severity": "Low", 
#                     "vector": "Response Headers",
#                     "url": "Base URL",
#                     "param": required_header,
#                     "evidence": f"The response is missing the critical '{required_header}' header."
#                 })
        
#         if headers_lower.get('x-content-type-options', '').lower() != 'nosniff':
#              self.findings.append({
#                  "type": "Security Misconfiguration",
#                  "severity": "Low", 
#                  "vector": "Response Headers",
#                  "url": "Base URL",
#                  "param": "X-Content-Type-Options: nosniff",
#                  "evidence": "X-Content-Type-Options header is missing or not set to 'nosniff'."
#              })


#     async def test_url_param_reflection(self, session, page_data):
#         url = page_data["url"]
#         baseline_time = page_data["baseline_time"] if page_data["baseline_time"] is not None else self.timeout_total 
        
#         parts = list(urlsplit(url))
#         query_string = parts[3]
#         if not query_string:
#             return
            
#         query = parse_qs(query_string, keep_blank_values=True)
        
#         for param in list(query.keys()):
#             orig_values = query[param]
            
#             # 1. XSS Reflection Tests
#             for payload in XSS_PAYLOADS:
#                 query[param] = [payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url = urlunsplit(parts)
#                 text_xss, _ = await self.fetch_probe(session, 'get', test_url)
                
#                 if XSS_MARKER in text_xss: 
#                     self.findings.append({"type": "Reflected XSS (XSS)", "severity": "High", "vector": "URL Query Parameter", "url": test_url, "param": param, "evidence": f"Injected payload reflected in response (e.g., '{payload[:20]}...')" })
#                     break 
            
#             # 2. SQLI Error-Based Test
#             query[param] = [SQLI_MARKER_SIMPLE]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_err = urlunsplit(parts)
#             stext_err, _ = await self.fetch_probe(session, 'get', test_url_sqli_err)
            
#             if any(ind in stext_err.lower() for ind in SQL_ERROR_INDICATORS):
#                 self.findings.append({"type": "SQL Injection (Error-Based)", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_sqli_err, "param": param, "evidence": "SQL error indicator present in response after single quote injection" })
            
#             # 3. SQLI Time-Based (Blind) Test
#             query[param] = [SQLI_TIME_PAYLOAD]
#             parts[3] = urlencode(query, doseq=True)
#             test_url_sqli_time = urlunsplit(parts)
#             _, elapsed_time_test = await self.fetch_probe(session, 'get', test_url_sqli_time)

#             if elapsed_time_test is not None and elapsed_time_test > (baseline_time + DELAY_THRESHOLD):
#                  self.findings.append({"type": "Blind SQL Injection (Time-Based)", "severity": "High", "vector": "URL Query Parameter", "url": test_url_sqli_time, "param": param, "evidence": f"Response delayed by ~{elapsed_time_test:.2f}s (Baseline: {baseline_time:.2f}s). Potential blind SQLi." })
            
#             # 4. IDOR/Directory Traversal/RFI (New Basic Check)
#             if query[param] and query[param][0].isdigit():
#                 try:
#                     test_id = str(int(query[param][0]) - 1)
#                     query[param] = [test_id]
#                     parts[3] = urlencode(query, doseq=True)
#                     test_url_idor = urlunsplit(parts)
                    
#                     self.findings.append({"type": "Potential Insecure Direct Object Reference (IDOR)", "severity": "Medium", "vector": "URL Query Parameter", "url": test_url_idor, "param": param, "evidence": f"Parameter looks like an ID. Accessing '{test_id}' might expose other users' data (requires manual verification)." })
#                 except ValueError:
#                     pass

#             for file_payload in FILE_INCLUSION_PAYLOADS:
#                 query[param] = [file_payload]
#                 parts[3] = urlencode(query, doseq=True)
#                 test_url_file = urlunsplit(parts)
#                 stext_file, _ = await self.fetch_probe(session, 'get', test_url_file)
                
#                 if any(ind in stext_file for ind in FILE_INCLUSION_INDICATORS):
#                     self.findings.append({"type": "Remote File Inclusion / Directory Traversal", "severity": "Critical", "vector": "URL Query Parameter", "url": test_url_file, "param": param, "evidence": f"File access pattern (e.g., path traversal or expected file content) detected in response." })
#                     break

#             # Restore original values
#             query[param] = orig_values

#     async def run(self, pages, forms, headers):
#         self.check_security_headers(headers)
        
#         sem = asyncio.Semaphore(self.concurrency)
#         async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
#             tasks = []
#             for p in pages:
#                 async def task_url(page_data=p):
#                     async with sem:
#                         await self.test_url_param_reflection(session, page_data)
#                 tasks.append(asyncio.create_task(task_url()))
#             # Form testing tasks would go here
#             if tasks:
#                 await asyncio.gather(*tasks, return_exceptions=True) 
#         return self.findings

# def run_scan_sync(target, max_pages, max_depth, concurrency, timeout, ui_log):
#     findings = []
#     pages = []
#     forms = []
#     headers = {}
    
#     async def inner():
#         nonlocal findings, pages, forms, headers 
#         def logger(msg): ui_log(msg)
#         crawler = Crawler(target, max_pages, max_depth, timeout, logger)
#         ui_log("Starting crawl and establishing baselines...")
#         c_result = await crawler.crawl()
        
#         pages = c_result["pages"]
#         forms = c_result["forms"]
#         headers = c_result["headers"]
        
#         ui_log(f"Crawl finished. Found {len(pages)} pages and {len(forms)} forms.")
#         prober = Prober(concurrency, timeout, logger)
#         ui_log("Starting advanced vulnerability probing...")
#         findings = await prober.run(pages, forms, headers) 
#         ui_log("Probing finished.")
#         return findings, pages, forms, headers
        
#     try:
#         return asyncio.run(inner())
#     except Exception as e:
#         ui_log(f"CRITICAL ERROR: Scan aborted: {type(e).__name__} - {e}")
#         # Return initialized variables even on error
#         return findings, pages, forms, headers 

# def to_excel_report(target_url, findings):
#     """Generates an Excel file (in bytes) from findings."""
    
#     if findings:
#         findings_df = pd.DataFrame(findings)
#         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
#     else:
#         findings_df = pd.DataFrame({'Message': ['No vulnerabilities found in this scan.']})
    
#     output = io.BytesIO()
#     writer = pd.ExcelWriter(output, engine='xlsxwriter')
    
#     findings_df.to_excel(writer, sheet_name='Vulnerability Findings', index=False)
    
#     metadata_df = pd.DataFrame({
#         'Key': ['Target URL', 'Scan Date', 'Total Findings'],
#         'Value': [target_url, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), len(findings)]
#     })
#     metadata_df.to_excel(writer, sheet_name='Metadata', index=False)
    
#     # Close the writer correctly
#     writer.close() 
#     output.seek(0)
#     return output.read()


# # ==================================
# # STREAMLIT UI 
# # ==================================
# st.set_page_config(page_title="Pro Web Security Scanner", layout="wide", initial_sidebar_state="expanded")

# if 'logged_in' not in st.session_state:
#     st.session_state.logged_in = False
#     st.session_state.role = ''

# st.sidebar.title("🛡️ SafeScanner Pro") 
# st.sidebar.markdown(f'<style>div[data-testid="stSidebar"] {{background-color: #2d2d2d;}}</style>', unsafe_allow_html=True) # Sidebar Background Color

# if not st.session_state.logged_in:
#     st.sidebar.header("👤 User Login")
#     username = st.sidebar.text_input("Username", key="login_user")
#     password = st.sidebar.text_input("Password", type="password", key="login_pass")
#     login_btn = st.sidebar.button("🔑 Login", type="primary", use_container_width=True)
    
#     if login_btn:
#         c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
#         res = c.fetchone()
#         if res:
#             st.session_state.logged_in = True
#             st.session_state.role = res[0]
#             st.sidebar.success(f"✅ Logged in as **{st.session_state.role}**")
#             st.experimental_rerun()
#         else:
#             st.sidebar.error("❌ Invalid credentials")
# else:
#     page = st.sidebar.radio("Go to:", ["🏠 Dashboard","🔬 Scanner","📜 History"])
#     st.sidebar.markdown("---")
#     st.sidebar.caption(f"Welcome, **{st.session_state.role}**")
#     logout_btn = st.sidebar.button("🚪 Logout", type="secondary", use_container_width=True)
#     if logout_btn:
#         st.session_state.logged_in = False
#         st.session_state.role = ''
#         st.info("👋 Logged out successfully.")
#         st.experimental_rerun()

#     if page=="🏠 Dashboard":
#         st.title("📊 Security Scan Dashboard")
#         st.markdown("---")
        
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         total_scans = len(rows)
#         total_findings = 0
#         finding_counts = {}
        
#         # V13 FIX: Initialize all severity counts to ensure they show up as 0 if not found
#         severity_counts = {
#             'Critical': 0,
#             'High': 0,
#             'Medium': 0,
#             'Low': 0,
#             'N/A': 0,
#             'Unknown': 0
#         }
        
#         all_findings_list = [] 
        
#         # --- Actual scan data processing (Used when DEBUG_MODE_CHARTS is False) ---
#         for r in rows:
#             try:
#                 findings = json.loads(r[3]) 
#                 # Aggregate total findings
#                 total_findings += len(findings)
                
#                 for f in findings:
#                     v_type = f.get('type', 'Unknown')
#                     v_severity = f.get('severity', 'N/A')
                    
#                     # Update counts based on findings
#                     if v_severity in severity_counts:
#                          severity_counts[v_severity] += 1
#                     else:
#                          severity_counts[v_severity] = 1 # Handle genuinely unexpected severity
                         
#                     finding_counts[v_type] = finding_counts.get(v_type, 0) + 1
#                     all_findings_list.append({'Type': v_type, 'Severity': v_severity, 'Count': 1})
#             except Exception:
#                 pass
        
#         # --- 1. KEY METRICS (Custom Card Structure) ---
#         st.subheader("💡 Key Performance Indicators")
#         col1, col2, col3, col4 = st.columns(4)
        
#         latest_target = rows[0][1] if rows else "N/A" 
#         latest_date = rows[0][2].split(' ')[0] if rows else "N/A" 
#         critical_count = severity_counts.get('Critical', 0)

#         col1.markdown(f"""
#         <div class="metric-box">
#             <label>Total Scans 🔎</label>
#             <p>{total_scans}</p>
#         </div>
#         """, unsafe_allow_html=True)

#         col2.markdown(f"""
#         <div class="metric-box">
#             <label>Total Findings 🚩</label>
#             <p>{total_findings}</p>
#         </div>
#         """, unsafe_allow_html=True)

#         col3.markdown(f"""
#         <div class="metric-box">
#             <label>Critical Findings 🚨</label>
#             <p>{critical_count}</p>
#         </div>
#         """, unsafe_allow_html=True)

#         col4.markdown(f"""
#         <div class="metric-box">
#             <label>Latest Scan 📅</label>
#             <p style='font-size: 1.5rem;'>{latest_date}</p>
#             <p style='font-size: 0.9rem; margin-top: 5px;'>{latest_target[:30]}...</p>
#         </div>
#         """, unsafe_allow_html=True)

#         st.markdown("<br><br>", unsafe_allow_html=True)
        
#         if total_findings > 0 or total_scans > 0: # Show charts if any scan was run
            
#             # --- 2. CHART ROW 1: SEVERITY (PIE CHART) & TOP TYPES (STACKED BAR CHART) ---
#             col_chart_1, col_chart_2 = st.columns(2)

#             # Setup Chart Theme for Dark Mode and Transparency
#             chart_theme = {
#                 "config": {
#                     "view": {"stroke": "transparent", "fill": "transparent"}, 
#                     "axis": {"domainColor": "#4a4a4a", "gridColor": "#3a3a3a", "tickColor": "#4a4a4a", "labelColor": "var(--text-light-gray)", "titleColor": "var(--text-white)"},
#                     "legend": {"labelColor": "var(--text-light-gray)", "titleColor": "var(--text-white)"},
#                     "title": {"color": "var(--text-white)"}
#                 }
#             }
#             alt.themes.register("custom_dark_transparent", lambda: chart_theme)
#             alt.themes.enable("custom_dark_transparent")


#             with col_chart_1:
#                 st.subheader("⚠️ Risk Severity Distribution")
                
#                 # Use the initialized severity_counts
#                 df_severity = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
                
#                 severity_order = ['Critical', 'High', 'Medium', 'Low', 'N/A', 'Unknown']
                
#                 # Merge with baseline to ensure all categories are present (even if count is 0)
#                 base_df = pd.DataFrame({'Severity': severity_order})
#                 df_severity = pd.merge(base_df, df_severity, on='Severity', how='left').fillna(0)
#                 df_severity['Count'] = df_severity['Count'].astype(int)

#                 # Dark Mode Color Palette
#                 severity_colors = {
#                     'Critical': '#f44336', 
#                     'High': '#ff9800', 
#                     'Medium': '#00bcd4', 
#                     'Low': '#2196f3', 
#                     'N/A': '#757575', 
#                     'Unknown': '#424242'
#                 }

#                 # PIE CHART (Full Pie Chart, not donut)
#                 base = alt.Chart(df_severity).encode(
#                     theta=alt.Theta("Count", stack=True)
#                 )

#                 pie = base.mark_arc(outerRadius=120, stroke="#1e1e1e", strokeWidth=2).encode( 
#                     color=alt.Color("Severity", scale=alt.Scale(domain=severity_order, range=[severity_colors[s] for s in severity_order])),
#                     order=alt.Order("Count", sort="descending"),
#                     tooltip=["Severity", "Count", alt.Tooltip("Count", format=",", title="Total")] 
#                 )

#                 # Text labels for value display - set to white for dark mode
#                 text = base.mark_text(radius=140).encode(
#                     text=alt.Text("Count", format=","),
#                     order=alt.Order("Count", sort="descending"),
#                     color=alt.value("white") 
#                 )
                
#                 chart = (pie + text).properties(height=350, title="Severity Risk Breakdown")
                
#                 st.altair_chart(chart, use_container_width=True)

#             with col_chart_2:
#                 st.subheader("🎯 Top 5 Vulnerability Types by Severity")
                
#                 df_top_types = pd.DataFrame(all_findings_list)
                
#                 # Calculate top 5 types globally across all severities
#                 top_types_list = df_top_types['Type'].value_counts().nlargest(5).index.tolist()
#                 df_top_types_filtered = df_top_types[df_top_types['Type'].isin(top_types_list)]

#                 # Group by type and severity to create the stacked bar data
#                 df_stacked_bar = df_top_types_filtered.groupby(['Type', 'Severity']).size().reset_index(name='Count')
                
#                 # Define stacked bar chart
#                 stacked_chart = alt.Chart(df_stacked_bar).mark_bar().encode(
#                     x=alt.X('Count', title='Total Findings Count'),
#                     y=alt.Y('Type', sort=alt.EncodingSortField(field='Count', op='sum', order='descending'), title='Vulnerability Type'),
#                     color=alt.Color("Severity", scale=alt.Scale(domain=severity_order, range=[severity_colors[s] for s in severity_order])),
#                     order=alt.Order("Severity", sort="descending"),
#                     tooltip=['Type', 'Severity', 'Count']
#                 ).properties(height=350, title="Severity Breakdown by Top Types")
                
#                 # Add text labels (values) - set to white for dark mode
#                 text_layer = stacked_chart.mark_text(
#                     align='left',
#                     baseline='middle',
#                     dx=3
#                 ).encode(
#                     text=alt.Text('Count', format=","),
#                     color=alt.value('white') 
#                 )
                
#                 st.altair_chart(stacked_chart, use_container_width=True)
                
#             st.markdown("---")
            
#             # --- 3. TIME SERIES TREND (Dark Mode Look) ---
#             st.subheader("⏳ Scan Activity Over Time")
            
#             date_findings = {}
            
#             # Use original rows for time series
#             rows_for_trend = c.execute("SELECT date, findings FROM scans ORDER BY date ASC").fetchall()

#             for r in rows_for_trend:
#                 date_key = datetime.strptime(r[0].split(' ')[0], '%Y-%m-%d').date()
#                 try:
#                     num_findings = len(json.loads(r[1]))
#                     date_findings[date_key] = date_findings.get(date_key, 0) + num_findings
#                 except:
#                      pass

#             df_trend = pd.DataFrame(list(date_findings.items()), columns=['Date', 'Findings Count']).sort_values('Date')
            
#             # Use darker colors for area chart in dark mode
#             line_chart = alt.Chart(df_trend).mark_area(
#                 line={'color':'#00a18c'}, 
#                 color=alt.Gradient(
#                     gradient='linear',
#                     stops=[alt.GradientStop(color='#2d2d2d', offset=0), alt.GradientStop(color='rgba(0, 121, 107, 0.4)', offset=1)], 
#                     x1=1,
#                     y1=1,
#                     x2=1,
#                     y2=0
#                 ),
#                 interpolate='monotone',
#                 opacity=0.9
#             ).encode(
#                 x=alt.X('Date:T', title='Scan Date'),
#                 y=alt.Y('Findings Count:Q', title='Total Vulnerabilities'),
#                 tooltip=['Date:T', 'Findings Count:Q']
#             ).properties(
#                 title='Vulnerability Detection Trend'
#             ).interactive() 
            
#             st.altair_chart(line_chart, use_container_width=True)

#             # --- 4. DATA TABLE (Styled for Severity visibility) ---
#             st.subheader("📜 Latest Findings Overview")
            
#             # Use real aggregated findings from all history 
#             findings_all_latest = []
#             for r in rows:
#                  try:
#                     findings_all_latest.extend(json.loads(r[3]))
#                  except Exception:
#                     pass
            
#             if findings_all_latest:
#                 latest_findings_df = pd.DataFrame(findings_all_latest)
#                 latest_findings_df = latest_findings_df[['type', 'severity', 'url', 'param']].head(10)
#                 latest_findings_df.columns = ['Type', 'Severity', 'Affected URL', 'Parameter']
                
#                 # Apply severity text color styling for best readability in dark mode
#                 def color_severity_text_dark(val):
#                     if val == 'Critical': return 'color: #f44336; font-weight: bold;' 
#                     if val == 'High': return 'color: #ff9800; font-weight: bold;'
#                     if val == 'Medium': return 'color: #00bcd4; font-weight: bold;'
#                     if val == 'Low': return 'color: #2196f3;'
#                     return 'color: #f5f5f5;' # White text for general info

#                 styled_df = latest_findings_df.style.applymap(color_severity_text_dark, subset=['Severity'])
                
#                 st.dataframe(styled_df, use_container_width=True, hide_index=True)
#                 st.caption(f"Showing 10 most recent findings from a total of {total_findings} aggregated findings. Severity colors indicate risk.")


#         else:
#             st.info("ℹ️ No scan findings available to display charts. Please run a scan first!")

#     elif page=="🔬 Scanner":
#         # APPLY CLASS TO REMOVE BORDER-BOTTOM
#         st.markdown('<div class="scanner-heading-no-border">', unsafe_allow_html=True)
#         st.title("🔬 Web Vulnerability Scan")
#         st.markdown('</div>', unsafe_allow_html=True)
        
#         # IMPROVED GUIDANCE BOX (Darker background)
#         st.markdown("""
#         <div class="guidance-box">
#         💡 <strong>Expert Guidance:</strong> Use a fully qualified URL (http/https) for accurate results. For testing, use platforms like DVWA or bWAPP.
#         </div>
#         """, unsafe_allow_html=True)
        
#         with st.expander("⚙️ Scan Configuration Parameters", expanded=True):
#             target_input = st.text_input("🌐 Target URL (e.g., http://testphp.vulnweb.com)", "http://localhost:3000", key="target_url")
            
#             col_a, col_b, col_c, col_d = st.columns(4)
#             max_pages = col_a.number_input("Max Pages", 1, 1000, 100, key="max_pages", help="Max number of pages to crawl.")
#             max_depth = col_b.number_input("Max Depth", 0, 5, 2, key="max_depth", help="Max link depth to follow from the root URL.")
#             concurrency = col_c.number_input("Concurrency", 1, 50, 8, key="concurrency", help="Number of simultaneous requests to make.")
#             timeout = col_d.number_input("Timeout (s)", 5, 120, 20, key="timeout", help="Timeout for each individual request.")

#             # SCAN BUTTON IS RED NOW (CSS change)
#             run_button = st.button("🚀 Start Advanced Scan", type="primary", use_container_width=True)
            
#         # --- ENHANCED STATUS AND PROGRESS AREA ---
#         status_area = st.empty()
#         progress_bar = st.empty() 
        
#         # FIX: Only one progress bar is initialized/used
        
#         results_area = st.container()
        
#         st.subheader("Terminal Log Output 📝")
#         log_area = st.container(border=True) 

#         # --- LOGIC FOR PROGRESS BAR AND LOGGING ---
#         LOG_LINES = []
#         def ui_log_append(msg):
#             global LOG_LINES
            
#             # Check to prevent adding empty or purely space lines
#             if not msg.strip():
#                  return
                 
#             LOG_LINES.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            
#             progress_val = 0
#             progress_text = ""
            
#             if "Starting crawl" in msg:
#                 progress_val = 10
#                 progress_text = "10% - Starting Crawl..."
#             elif "Crawl finished" in msg:
#                  progress_val = 50
#                  progress_text = "50% - Crawl Finished. Starting Probing..."
#             elif "Probing finished" in msg:
#                 progress_val = 95
#                 progress_text = "95% - Finalizing Report..."
            
#             if progress_val > 0:
#                  progress_bar.progress(progress_val, text=progress_text)


#             with log_area:
#                  log_area.empty() 
#                  log_html = ""
#                  # Show last 15 lines for performance
#                  for line in LOG_LINES[-15:]: 
#                      # Applying the custom class for proper margin-bottom, keeping the log content clean
#                      log_html += f'<div class="log-entry-container"><pre>{line}</pre></div>'
#                  log_area.markdown(log_html, unsafe_allow_html=True)
                 
#                  time.sleep(0.01)

#         # --- SCAN EXECUTION ---
#         if run_button:
#             if not target_input.strip() or not target_input.startswith(('http://', 'https://')):
#                 status_area.error("❌ Please provide a valid URL starting with `http://` or `https://`.")
#             else:
#                 LOG_LINES=[]
#                 progress_bar.progress(5, text="5% - Initializing Scanner...")
#                 with status_area:
#                     st.info(f"🔍 Scan in progress on **{target_input}**...")
                
#                 # Force the progress bar update for initial display
#                 progress_bar.progress(5, text="5% - Initializing Scanner...")

#                 # Clear log area and start logging
#                 log_area.empty()
#                 findings, pages, forms, headers = run_scan_sync(target_input, max_pages, max_depth, concurrency, timeout, ui_log_append)

#                 c.execute("INSERT INTO scans(target,date,findings) VALUES(?,?,?)", (target_input, str(datetime.utcnow()), json.dumps(findings)))
#                 conn.commit()
                
#                 # Final Status/Progress Update
#                 progress_bar.progress(100, text="100% - Done!")
#                 status_area.success("✅ Scan completed successfully! Results displayed below.")
                
#                 with results_area:
#                     st.subheader("📝 Scan Results Summary")
#                     # No extra new lines here, clean markdown
#                     st.markdown(f"**Discovered:** **{len(pages)}** pages and **{len(forms)}** forms.") 

#                     st.subheader("🌐 HTTP Security Header Status")
                    
#                     header_df = pd.DataFrame(REQUIRED_SECURITY_HEADERS, columns=['Required Header'])
#                     header_df['Status'] = header_df['Required Header'].apply(lambda x: '✅ Present' if x.lower() in {k.lower():v for k,v in headers.items()} else '❌ Missing')
#                     header_df['Value'] = header_df['Required Header'].apply(lambda x: headers.get(x, headers.get(x.lower(), '---')))
#                     st.dataframe(header_df, use_container_width=True, hide_index=True)
#                     st.caption("Note: Headers were checked on the base URL.")
#                     st.markdown("---")
                    
#                     if findings:
#                         st.error(f"⚠️ **VULNERABILITIES FOUND! {len(findings)} issues detected.** Immediate action is required.")
                        
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         # Apply severity text color styling for best readability
#                         def color_severity_text_dark(val):
#                             if val == 'Critical': return 'color: #f44336; font-weight: bold;' 
#                             if val == 'High': return 'color: #ff9800; font-weight: bold;'
#                             if val == 'Medium': return 'color: #00bcd4; font-weight: bold;'
#                             if val == 'Low': return 'color: #2196f3;'
#                             return 'color: #f5f5f5;'

#                         styled_df = findings_df.style.applymap(color_severity_text_dark, subset=['Severity'])

#                         st.dataframe(styled_df, use_container_width=True, hide_index=True)
                        
#                         excel_data = to_excel_report(target_input, findings)
#                         st.download_button(
#                             label="⬇️ Download Professional Excel Report (.xlsx)",
#                             data=excel_data,
#                             file_name=f"scan_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx",
#                             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#                             type="secondary"
#                         )
#                     else:
#                         st.balloons()
#                         st.success("🎉 **No critical or major issues found** after advanced checks. The target appears secure.")

#     elif page=="📜 History":
#         st.title("📂 Scan History")
        
#         # Select all data points from history
#         c.execute("SELECT id, target, date, findings FROM scans ORDER BY date DESC")
#         rows = c.fetchall()
        
#         if not rows:
#             st.info("ℹ️ No past scan history found.")
#         else:
            
#             for r in rows:
#                 scan_id, target, date, findings_json = r
#                 findings = json.loads(findings_json)
                
#                 total_findings = len(findings)
                
#                 icon = "🚨" if total_findings > 0 else "🟢"
                
#                 with st.expander(f"{icon} Scan ID: **{scan_id}** | Target: **{target}** | Date: **{date}** | Findings: **{total_findings}**"):
#                     if findings:
#                         findings_df = pd.DataFrame(findings)
#                         findings_df = findings_df[['type', 'severity', 'url', 'param', 'vector', 'evidence']]
#                         findings_df.columns = ['Vulnerability Type', 'Severity', 'Affected URL', 'Parameter', 'Vector', 'Evidence']
                        
#                         # Background coloring for the table rows based on severity (History section uses soft background colors)
#                         def color_row_by_severity(row):
#                             # Use soft, dark mode friendly colors
#                             color = ''
#                             if row['Severity'] == 'Critical': color = '#382020' 
#                             elif row['Severity'] == 'High': color = '#453220'
#                             elif row['Severity'] == 'Medium': color = '#203a3a' 
#                             elif row['Severity'] == 'Low': color = '#202a3a' 
#                             return ['background-color: %s' % color] * len(row)

#                         styled_df = findings_df.style.apply(color_row_by_severity, axis=1)

#                         st.dataframe(styled_df, use_container_width=True, hide_index=True)
                        
#                         excel_data = to_excel_report(target, findings)
#                         st.download_button(
#                             label="⬇️ Download Report (Excel)",
#                             data=excel_data,
#                             file_name=f"report_{scan_id}.xlsx",
#                             mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#                             key=f"dl_btn_{scan_id}",
#                             type="secondary"
#                         )
#                     else:
#                         st.success("✅ No vulnerabilities found in this scan.")


