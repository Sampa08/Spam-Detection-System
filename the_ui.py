import tkinter as tk
from tkinter import ttk

# Main app window
root = tk.Tk()
root.title("Spam Detection System")
root.geometry("1000x600")
root.config(bg="#F5F7FA")

# Top navigation bar
top_bar = tk.Frame(root, bg="#4632DA", height=40)
top_bar.pack(side="top", fill="x")

title = tk.Label(top_bar, text="Spam Detection System", bg="#4632DA", fg="white", font=("Arial", 12, "bold"))
title.pack(side="left", padx=10)

# Sidebar
sidebar = tk.Frame(root, bg="white", width=220)
sidebar.pack(side="left", fill="y")

# Sidebar items
menu_items = [
    ("📊  Dashboard",),
    ("📧  Scan Emails",),
    ("📱  Scan SMS",),
    ("📜  History",),
    ("👤  Profile",)
]



import imaplib
import email
from email.header import decode_header


import re
from urllib.parse import urlparse

def is_suspicious(url):
    suspicious_tlds = {'.xyz', '.top', '.ru', '.cn'}
    suspicious_domains = {'g00gle.com', 'secure-login.xyz'}
    parsed = urlparse(url)
    domain = parsed.netloc
    tld = '.' + domain.split('.')[-1]
    if domain in suspicious_domains or tld in suspicious_tlds:
        return True
    return False


# --- Email/password input UI ---
def build_email_scan_ui():
    for widget in main_content.winfo_children():
        widget.destroy()
    form_frame = tk.Frame(main_content, bg="#F5F7FA")
    form_frame.pack(anchor="nw", padx=10, pady=10)
    tk.Label(form_frame, text="Gmail Address:", bg="#F5F7FA").grid(row=0, column=0, sticky="w")
    email_entry = tk.Entry(form_frame, width=30)
    email_entry.grid(row=0, column=1, padx=5, pady=2)
    tk.Label(form_frame, text="App Password:", bg="#F5F7FA").grid(row=1, column=0, sticky="w")
    pass_entry = tk.Entry(form_frame, width=30, show="*")
    pass_entry.grid(row=1, column=1, padx=5, pady=2)
    result_frame = tk.Frame(main_content, bg="#F5F7FA")
    result_frame.pack(anchor="nw", padx=10, pady=10, fill="x")

    def do_scan():
        username = email_entry.get().strip()
        password = pass_entry.get().strip()
        for widget in result_frame.winfo_children():
            widget.destroy()
        if not username or not password:
            tk.Label(result_frame, text="Please enter both email and app password.", fg="red", bg="#F5F7FA").pack(anchor="w")
            return
        # Hide the login form
        form_frame.pack_forget()
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(username, password)
            mail.select("inbox")
            status, messages = mail.search(None, "ALL")
            email_ids = messages[0].split()
            total = len(email_ids)
            suspicious_count = 0
            suspicious_details = []
            for num in email_ids[-20:]:  # Scan last 20 emails for demo
                status, msg_data = mail.fetch(num, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                ctype = part.get_content_type()
                                cdispo = str(part.get('Content-Disposition'))
                                if ctype == 'text/plain' and 'attachment' not in cdispo:
                                    try:
                                        body = part.get_payload(decode=True).decode()
                                    except:
                                        body = ""
                                    break
                        else:
                            try:
                                body = msg.get_payload(decode=True).decode()
                            except:
                                body = ""
                        urls = re.findall(r'https?://[^\s]+', body)
                        found = [url for url in urls if is_suspicious(url)]
                        if found:
                            suspicious_count += 1
                            subject, encoding = decode_header(msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else "utf-8", errors="ignore")
                            suspicious_details.append(f"Subject: {subject}\nSuspicious URLs: {', '.join(found)}")
            result_text = f"Total emails scanned: {total}\nSuspicious emails found: {suspicious_count}"
            tk.Label(result_frame, text=result_text, bg="#F5F7FA", fg="black", font=("Arial", 14), justify="left").pack(anchor="nw", pady=5)
            if suspicious_details:
                details = "\n\n".join(suspicious_details)
                details_box = tk.Text(result_frame, height=15, width=80)
                details_box.insert("1.0", details)
                details_box.config(state="disabled")
                details_box.pack(padx=0, pady=5)
            mail.logout()
        except Exception as e:
            tk.Label(result_frame, text=f"Error: {e}", bg="#F5F7FA", fg="red", font=("Arial", 14)).pack(anchor="w")

    scan_btn = tk.Button(form_frame, text="Scan", command=do_scan, bg="#4632DA", fg="white", font=("Arial", 11, "bold"))
    scan_btn.grid(row=2, column=0, columnspan=2, pady=8)


# Create sidebar buttons and assign build_email_scan_ui to 'Scan Emails'
for item in menu_items:
    if item[0] == "📧  Scan Emails":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_email_scan_ui)
    else:
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10)
    btn.pack(fill="x")

# Bottom user profile section
profile_frame = tk.Frame(sidebar, bg="white")
profile_frame.pack(side="bottom", fill="x", pady=20)

profile_label = tk.Label(profile_frame, text="Andrew D.\nadmin@gmail.com", 
                         bg="white", fg="black", font=("Arial", 10), justify="left")
profile_label.pack(padx=10)

profile_link = tk.Label(profile_frame, text="View Profile", fg="blue", bg="white", cursor="hand2")
profile_link.pack(anchor="w", padx=10)


# Main content area
main_content = tk.Frame(root, bg="#F5F7FA")
main_content.pack(side="left", expand=True, fill="both")

# Show the scan UI by default (optional, or keep placeholder)
placeholder = tk.Label(main_content, text="Main Content Area", bg="#F5F7FA", 
                       fg="gray", font=("Arial", 14))
placeholder.pack(expand=True)

root.mainloop()
