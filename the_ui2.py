import tkinter as tk
from tkinter import ttk
from email_classifier import classify_email

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

# Sidebar items (add the new module here)
menu_items = [
    ("📊  Dashboard",),
    ("📧  Scan Emails",),
    ("📱  Scan SMS",),
    ("📜  History",),
    ("👤  Profile",),
    ("🎓  User Training Simulation Module",)  # <-- Add this line
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
    login_label = tk.Label(main_content, text="Log in details", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    login_label.pack(anchor="n", pady=(30, 10))
    form_frame = tk.Frame(main_content, bg="#F5F7FA")
    form_frame.place(relx=0.5, rely=0.3, anchor="center")
    tk.Label(form_frame, text="Gmail Address:", bg="#F5F7FA").grid(row=0, column=0, sticky="w")
    email_entry = tk.Entry(form_frame, width=30)
    email_entry.grid(row=0, column=1, padx=5, pady=2)
    tk.Label(form_frame, text="App Password:", bg="#F5F7FA").grid(row=1, column=0, sticky="w")
    pass_entry = tk.Entry(form_frame, width=30, show="*")
    pass_entry.grid(row=1, column=1, padx=5, pady=2)
    result_frame = tk.Frame(main_content, bg="#F5F7FA")
    result_frame.pack(anchor="n", padx=10, pady=10, fill="x")

    # Add loading label (initially hidden)
    loading_label = tk.Label(main_content, text="Loading...", bg="#F5F7FA", fg="#4632DA", font=("Arial", 12, "italic"))
    progress = ttk.Progressbar(main_content, orient="horizontal", length=400, mode="determinate")
    refresh_btn = tk.Button(main_content, text="Refresh", bg="#4632DA", fg="white", font=("Arial", 11, "bold"))

    def scan_emails(username, password):
        for widget in result_frame.winfo_children():
            widget.destroy()
        loading_label.pack(pady=(10, 0))
        progress.pack(pady=10)
        main_content.update_idletasks()
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(username, password)
            mail.select("inbox")
            status, messages = mail.search(None, "ALL")
            email_ids = messages[0].split()
            total = len(email_ids)
            spam_count = 0
            scam_count = 0
            ham_count = 0
            details = []
            scan_count = min(20, total)
            progress["maximum"] = scan_count
            progress["value"] = 0
            for idx, num in enumerate(email_ids[-scan_count:]):
                status, msg_data = mail.fetch(num, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding if encoding else "utf-8", errors="ignore")
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
                        # --- AI Classification ---
                        email_text = f"{subject}\n{body}"
                        label = classify_email(email_text)
                        if label == "spam":
                            spam_count += 1
                        elif label == "scam":
                            scam_count += 1
                        else:
                            ham_count += 1
                        details.append(f"Subject: {subject}\nClassified as: {label}")
                progress["value"] = idx + 1
                main_content.update_idletasks()
            result_text = (
                f"Total emails scanned: {total}\n"
                f"Spam: {spam_count}  Scam: {scam_count}  Ham: {ham_count}"
            )
            tk.Label(result_frame, text=result_text, bg="#F5F7FA", fg="black",
                     font=("Arial", 14), justify="left").pack(anchor="nw", pady=5)
            if details:
                details_box = tk.Text(result_frame, height=15, width=80)
                details_box.insert("1.0", "\n\n".join(details))
                details_box.config(state="disabled")
                details_box.pack(padx=0, pady=5)
            mail.logout()
        except Exception as e:
            tk.Label(result_frame, text=f"Error: {e}", bg="#F5F7FA", fg="red",
                     font=("Arial", 14)).pack(anchor="w")
        progress.pack_forget()
        loading_label.pack_forget()
        refresh_btn.pack(pady=10)

    def do_scan():
        username = email_entry.get().strip()
        password = pass_entry.get().strip()
        login_label.destroy()
        form_frame.destroy()
        refresh_btn.pack_forget()
        scan_emails(username, password)

        # Save credentials for refresh
        refresh_btn.username = username
        refresh_btn.password = password

    def do_refresh():
        refresh_btn.pack_forget()
        scan_emails(refresh_btn.username, refresh_btn.password)

    scan_btn = tk.Button(form_frame, text="Scan", command=do_scan, bg="#4632DA", fg="white", font=("Arial", 11, "bold"))
    scan_btn.grid(row=2, column=0, columnspan=2, pady=8)
    refresh_btn.config(command=do_refresh)

# Create sidebar buttons and assign build_email_scan_ui to 'Scan Emails'
for item in menu_items:
    if item[0] == "📧  Scan Emails":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_email_scan_ui)
    elif item[0] == "🎓  User Training Simulation Module":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=lambda: tk.messagebox.showinfo("Training", "User Training Simulation Module coming soon!"))
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
