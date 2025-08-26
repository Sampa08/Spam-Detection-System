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
from tkinter import simpledialog

def scan_emails():
    # Prompt user for email and password
    username = simpledialog.askstring("Email Login", "Enter your Gmail address:", parent=root)
    if not username:
        return
    password = simpledialog.askstring("Email Login", "Enter your app password:", parent=root, show='*')
    if not password:
        return
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(username, password)
        mail.select("inbox")
        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()
        total = len(email_ids)
        # Display result in main content area
        for widget in main_content.winfo_children():
            widget.destroy()
        result_label = tk.Label(main_content, text=f"Total emails: {total}", bg="#F5F7FA", fg="black", font=("Arial", 14))
        result_label.pack(expand=True)
        mail.logout()
    except Exception as e:
        for widget in main_content.winfo_children():
            widget.destroy()
        error_label = tk.Label(main_content, text=f"Error: {e}", bg="#F5F7FA", fg="red", font=("Arial", 14))
        error_label.pack(expand=True)

# Create sidebar buttons and assign scan_emails to 'Scan Emails'
for item in menu_items:
    if item[0] == "📧  Scan Emails":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=scan_emails)
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

placeholder = tk.Label(main_content, text="Main Content Area", bg="#F5F7FA", 
                       fg="gray", font=("Arial", 14))
placeholder.pack(expand=True)

root.mainloop()
