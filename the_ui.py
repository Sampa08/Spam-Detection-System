import tkinter as tk
from tkinter import ttk
from email_classifier import classify_email
from tkinter import filedialog, messagebox
import pandas as pd
import json
import re
from urllib.parse import urlparse
import vonage
import requests
import random
import time
from datetime import datetime
import imaplib
import email
from email.header import decode_header
import os
import zipfile
import datetime
from datetime import datetime, timedelta
from flask import Flask, request
import threading

HISTORY_PATH = "history.json"
LAST_EMAIL_PATH = "last_email.json"
SMS_HISTORY_PATH = "sms_history.json"
VONAGE_CONFIG_PATH = "vonage_config.json"

# Global color map used throughout the UI
COLOR_MAP = {"ham": "green", "spam": "yellow", "scam": "red"}

def load_history():
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            history_data = json.load(f)
            # Limit history to last 500 items to prevent memory issues
            if len(history_data) > 500:
                history_data = history_data[-500:]
            return history_data
    except Exception:
        return []

def save_history(history):
    # Limit history to last 500 items to prevent memory issues
    if len(history) > 500:
        history = history[-500:]
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

def load_sms_history():
    try:
        with open(SMS_HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_sms_history(sms_history):
    with open(SMS_HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(sms_history, f, indent=2)

def load_vonage_config():
    try:
        with open(VONAGE_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"api_key": "", "api_secret": "", "phone_number": "", "webhook_url": ""}

def save_vonage_config(config):
    with open(VONAGE_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

history = load_history()
sms_history = load_sms_history()
vonage_config = load_vonage_config()

# --- Add helper to cancel history auto-refresh ---
def cancel_history_refresh():
    try:
        job = getattr(root, "_history_refresh_job", None)
        if job:
            root.after_cancel(job)
            root._history_refresh_job = None
    except Exception:
        # root may not exist yet or job already cancelled
        pass

# SMS Fraud Detection Functions
def analyze_sms_for_fraud(message_text, sender_number):
    """
    Analyze incoming SMS for potential fraud indicators
    """
    fraud_indicators = {
        'is_fraud': False,
        'confidence': 0.0,
        'category': 'ham',
        'reasons': []
    }
    
    message_lower = message_text.lower()
    
    # 1. Check for suspicious patterns in message content
    scam_patterns = [
        r'won.*prize', r'lottery', r'free.*money', r'gift.*card',
        r'click.*link', r'http[s]?://', r'bit\.ly', r'tinyurl',
        r'verify.*account', r'bank.*alert', r'account.*suspended',
        r'urgent.*action', r'immediate.*response', r'limited.*time',
        r'congratulations', r'you.*winner', r'claim.*now',
        r'password.*reset', r'security.*alert', r'suspicious.*activity'
    ]
    
    spam_patterns = [
        r'sale.*now', r'discount', r'buy.*now', r'special.*offer',
        r'call.*now', r'text.*back', r'unsubscribe', r'stop.*to.*end',
        r'promotion', r'exclusive.*offer'
    ]
    
    # Check for scam patterns
    scam_matches = 0
    for pattern in scam_patterns:
        if re.search(pattern, message_lower):
            scam_matches += 1
            fraud_indicators['reasons'].append(f"Scam pattern: {pattern}")
    
    if scam_matches > 0:
        fraud_indicators['confidence'] += scam_matches * 0.15
        fraud_indicators['category'] = 'scam'
    
    # Check for spam patterns
    spam_matches = 0
    for pattern in spam_patterns:
        if re.search(pattern, message_lower):
            spam_matches += 1
            fraud_indicators['reasons'].append(f"Spam pattern: {pattern}")
    
    if spam_matches > 1 and fraud_indicators['confidence'] < 0.4:
        fraud_indicators['confidence'] += spam_matches * 0.1
        fraud_indicators['category'] = 'spam'
    
    # 2. Check for URLs (high risk indicator)
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, message_text)
    if urls:
        fraud_indicators['confidence'] += 0.3
        fraud_indicators['reasons'].append(f"Suspicious URLs found: {urls}")
        if fraud_indicators['category'] == 'ham':
            fraud_indicators['category'] = 'spam'
    
    # 3. Check message length (very short might be spam)
    if len(message_text) < 10:
        fraud_indicators['confidence'] += 0.1
        fraud_indicators['reasons'].append("Very short message (potential spam)")
    
    # 4. Check for excessive special characters
    special_char_ratio = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', message_text)) / len(message_text)
    if special_char_ratio > 0.2:
        fraud_indicators['confidence'] += 0.15
        fraud_indicators['reasons'].append("High special character density")
    
    # 5. Use the email classifier as fallback
    try:
        email_classification = classify_email(message_text)
        if email_classification.lower() in ['spam', 'scam']:
            fraud_indicators['confidence'] += 0.2
            if fraud_indicators['category'] == 'ham':
                fraud_indicators['category'] = email_classification.lower()
            fraud_indicators['reasons'].append(f"AI classifier detected: {email_classification}")
    except Exception as e:
        print(f"Classifier error: {e}")
    
    # Set final category based on confidence
    if fraud_indicators['confidence'] > 0.6:
        fraud_indicators['is_fraud'] = True
        if fraud_indicators['confidence'] > 0.8:
            fraud_indicators['category'] = 'scam'
    elif fraud_indicators['confidence'] > 0.3:
        fraud_indicators['category'] = 'spam'
    
    return fraud_indicators

def start_vonage_webhook_server(api_key, api_secret, phone_number):
    """
    Start a Flask server to receive Vonage webhooks
    """
    app = Flask(__name__)
    
    @app.route('/vonage-webhook', methods=['GET', 'POST'])
    def vonage_webhook():
        try:
            # Vonage can send data via GET (params) or POST (form data)
            if request.method == 'GET':
                # GET request - parameters in query string
                from_number = request.args.get('msisdn')
                message_body = request.args.get('text')
                message_id = request.args.get('messageId')
            else:
                # POST request - form data
                from_number = request.form.get('msisdn')
                message_body = request.form.get('text')
                message_id = request.form.get('messageId')
            
            if not from_number or not message_body:
                return '', 400
            
            print(f"Received SMS from {from_number}: {message_body}")
            
            # Analyze for fraud
            fraud_result = analyze_sms_for_fraud(message_body, from_number)
            
            # Save to SMS history
            sms_entry = {
                "id": message_id,
                "from_number": from_number,
                "message": message_body,
                "category": fraud_result['category'],
                "confidence": fraud_result['confidence'],
                "reasons": fraud_result['reasons'],
                "timestamp": datetime.now().isoformat(),
                "is_fraud": fraud_result['is_fraud']
            }
            
            sms_history.append(sms_entry)
            save_sms_history(sms_history)
            
            # Also save to general history
            history.append({
                "text": f"SMS from {from_number}: {message_body[:100]}...",
                "category": fraud_result['category'],
                "type": "sms",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            save_history(history)
            
            print(f"Analysis result: {fraud_result['category']} (confidence: {fraud_result['confidence']:.2f})")
            
            return '', 200
            
        except Exception as e:
            print(f"Error processing webhook: {e}")
            return '', 500
    
    # Run Flask app in a separate thread
    def run_flask():
        app.run(host='0.0.0.0', port=5000, debug=False)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    return "http://localhost:5000/vonage-webhook"

# Scrollable frame function
def create_scrollable_frame(parent):
    # Create main frame
    main_frame = tk.Frame(parent, bg=parent["bg"])
    
    # Create canvas and scrollbar
    canvas = tk.Canvas(main_frame, bg=parent["bg"], highlightthickness=0)
    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
    
    # Create the scrollable frame
    scrollable_frame = tk.Frame(canvas, bg=parent["bg"])
    
    # Configure the canvas
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    # Create window in canvas for the scrollable frame
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack everything
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Bind mouse wheel to canvas
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    canvas.bind("<MouseWheel>", _on_mousewheel)
    scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
    
    # Pack the main frame
    main_frame.pack(fill="both", expand=True)
    
    return scrollable_frame

def load_last_scanned_email():
    try:
        with open(LAST_EMAIL_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception:
        return {"text": "", "category": ""}

# Global variable to store last scanned email info
last_scanned_email = load_last_scanned_email()

def save_last_scanned_email(email_text, category):
    with open(LAST_EMAIL_PATH, "w", encoding="utf-8") as f:
        json.dump({"text": email_text, "category": category}, f)

def show_email_details(email_data, category):
    """Show detailed view of a specific email from history"""
    details_window = tk.Toplevel(root)
    details_window.title("Email Details")
    details_window.geometry("700x500")
    details_window.configure(bg="#F5F7FA")
    
    # Title
    title_frame = tk.Frame(details_window, bg="#F5F7FA")
    title_frame.pack(fill="x", padx=20, pady=10)
    
    tk.Label(title_frame, text="Email Details", bg="#F5F7FA", fg="#4632DA",
             font=("Arial", 16, "bold")).pack(anchor="w")
    
    # Content frame
    content_frame = tk.Frame(details_window, bg="white", relief="solid", bd=1)
    content_frame.pack(fill="both", expand=True, padx=20, pady=10)
    
    # Create scrollable content
    scroll_frame = create_scrollable_frame(content_frame)
    
    # Email fields
    fields = [
        ("Subject", email_data.get("subject", "No subject")),
        ("From", email_data.get("sender", "Unknown sender")),
        ("Date", email_data.get("date", "Unknown date")),
        ("Category", category),
        ("Body", email_data.get("body", "No body content"))
    ]
    
    for field_name, field_value in fields:
        field_frame = tk.Frame(scroll_frame, bg="white")
        field_frame.pack(fill="x", padx=15, pady=8)
        
        tk.Label(field_frame, text=f"{field_name}:", bg="white", fg="#4632DA",
                font=("Arial", 11, "bold"), width=12, anchor="w").pack(side="left")
        
        if field_name == "Body":
            # Use a text widget for the body to allow scrolling
            body_frame = tk.Frame(scroll_frame, bg="white")
            body_frame.pack(fill="both", expand=True, padx=15, pady=8)
            
            tk.Label(body_frame, text="Body:", bg="white", fg="#4632DA",
                    font=("Arial", 11, "bold")).pack(anchor="w")
            
            body_text = tk.Text(body_frame, height=15, wrap="word", font=("Arial", 10))
            body_scrollbar = ttk.Scrollbar(body_frame, orient="vertical", command=body_text.yview)
            body_text.configure(yscrollcommand=body_scrollbar.set)
            
            body_text.insert("1.0", field_value)
            body_text.config(state="disabled")
            
            body_text.pack(side="left", fill="both", expand=True)
            body_scrollbar.pack(side="right", fill="y")
        else:
            tk.Label(field_frame, text=field_value, bg="white", fg="black",
                    font=("Arial", 10), wraplength=500, justify="left").pack(side="left", fill="x", expand=True)

# --- IMPROVED Gmail Scanning Function with FIXED CLASSIFICATION ---
def scan_gmail_emails(username, password, result_frame):
    for widget in result_frame.winfo_children():
        widget.destroy()
    
    # Create loading elements
    loading_label = tk.Label(result_frame, text="Connecting to Gmail...", bg="#F5F7FA", fg="#4632DA", font=("Arial", 12, "italic"))
    progress = ttk.Progressbar(result_frame, orient="horizontal", length=400, mode="determinate")
    
    loading_label.pack(pady=(10, 0))
    progress.pack(pady=10)
    result_frame.update_idletasks()
    
    try:
        # Connect to Gmail
        loading_label.config(text="Connecting to Gmail server...")
        result_frame.update_idletasks()
        
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(username, password)
        mail.select("inbox")
        
        # Search for ALL emails in inbox
        loading_label.config(text="Searching for emails...")
        result_frame.update_idletasks()
        
        status, messages = mail.search(None, "ALL")
        
        if status != "OK":
            raise Exception("Failed to search emails")
        
        email_ids = messages[0].split()
        total_emails = len(email_ids)
        
        if total_emails == 0:
            # Show no emails found
            no_emails_frame = tk.Frame(result_frame, bg="#F5F7FA")
            no_emails_frame.pack(fill="x", padx=10, pady=10)
            tk.Label(no_emails_frame, text="❌ No emails found in inbox",
      bg="#F5F7FA", fg="red", font=("Arial", 12, "bold")).pack(anchor="nw")
            loading_label.pack_forget()
            progress.pack_forget()
            return
        
        loading_label.config(text=f"Found {total_emails} emails. Scanning...")
        result_frame.update_idletasks()
        
        # Enhanced data collection
        email_details = []
        
        scan_count = min(50, total_emails)  # Scan up to 50 emails for testing
        progress["maximum"] = scan_count
        progress["value"] = 0
        
        # Process emails from newest to oldest
        for idx, num in enumerate(reversed(email_ids[-scan_count:])):
            try:
                status, msg_data = mail.fetch(num, "(RFC822)")
                if status != "OK":
                    continue
                    
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        # Extract sender information
                        sender = msg["From"] or "Unknown"
                        subject_header = msg["Subject"] or ""
                        
                        # Decode subject
                        subject, encoding = decode_header(subject_header)[0]
                        if isinstance(subject, bytes):
                            try:
                                subject = subject.decode(encoding if encoding else "utf-8", errors="ignore")
                            except:
                                subject = subject.decode("utf-8", errors="ignore")
                        subject = subject or "No Subject"
                        
                        # Extract date
                        date_header = msg["Date"] or ""
                        
                        # Enhanced body extraction
                        body = ""
                        html_body = ""
                        
                        if msg.is_multipart():
                            for part in msg.walk():
                                ctype = part.get_content_type()
                                cdispo = str(part.get('Content-Disposition') or "")
                                
                                # Skip attachments
                                if 'attachment' in cdispo:
                                    continue
                                    
                                if ctype == 'text/plain' and not body:
                                    try:
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            body = payload.decode('utf-8', errors='ignore')
                                    except:
                                        pass
                                elif ctype == 'text/html' and not body:
                                    try:
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            html_body = payload.decode('utf-8', errors='ignore')
                                    except:
                                        pass
                        else:
                            # Not multipart - get payload directly
                            try:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    body = payload.decode('utf-8', errors='ignore')
                            except:
                                pass
                        
                        # Use plain text if available, otherwise extract text from HTML
                        if not body and html_body:
                            # Simple HTML tag removal
                            body = re.sub('<[^<]+?>', '', html_body)
                        
                        # Clean up the body text
                        if body:
                            body = re.sub(r'\s+', ' ', body)  # Normalize whitespace
                            body = body.strip()
                        
                        # Combine all relevant information for classification
                        email_content = f"FROM: {sender}\nSUBJECT: {subject}\nBODY: {body}"
                        
                        # CLASSIFY THE EMAIL (robust handling)
                        try:
                            category = classify_email(email_content)
                        except Exception as e:
                            # classifier crashed for this message — fallback
                            print(f"Classifier error for email {idx + 1}: {e}")
                            category = "unknown"
                        
                        # Normalize category to lowercase string and fallback if empty
                        if not isinstance(category, str) or not category.strip():
                            print(f"Classifier returned invalid label for email {idx + 1}: {category!r}")
                            category = "unknown"
                        category = category.strip().lower()
                        
                        # DEBUG: Check classification
                        print(f"=== EMAIL {idx + 1} ===")
                        print(f"Subject: {subject}")
                        print(f"Classification: {category}")
                        print("=" * 40)
                        
                        email_details.append({
                            "sender": sender,
                            "subject": subject,
                            "body": body,
                            "date": date_header,
                            "category": category,  # Store the actual classification
                            "full_text": email_content
                        })
                        
                        break  # Only process first part
                        
            except Exception as e:
                print(f"Error processing email {num}: {e}")
                continue
            
            progress["value"] = idx + 1
            loading_label.config(text=f"Processing emails... ({idx + 1}/{scan_count})")
            result_frame.update_idletasks()
        
        # Create results DataFrame
        display_df = pd.DataFrame({
            "text": [detail["full_text"] for detail in email_details],
            "predicted": [detail["category"] for detail in email_details],  # Use actual category
            "subject": [detail["subject"] for detail in email_details],
            "sender": [detail["sender"] for detail in email_details],
            "body": [detail["body"] for detail in email_details],
            "date": [detail["date"] for detail in email_details]
        })
        
        if display_df.empty:
            # Show no emails processed
            no_emails_frame = tk.Frame(result_frame, bg="#F5F7FA")
            no_emails_frame.pack(fill="x", padx=10, pady=10)
            tk.Label(no_emails_frame, text="❌ No emails could be processed", 
                     bg="#F5F7FA", fg="red", font=("Arial", 12, "bold")).pack(anchor="nw")
            loading_label.pack_forget()
            progress.pack_forget()
            return
        
        # Enhanced results display
        color_map = {"spam": "red", "scam": "orange", "ham": "green"}
        
        # Detailed summary - FIXED: Use actual categories
        summary = display_df["predicted"].value_counts().to_dict()
        total_scanned = len(display_df)
        
        summary_text = f"Total emails scanned: {total_scanned}\n"
        for cat, count in summary.items():
            summary_text += f"{cat.upper()}: {count}\n"
        
        # Display summary
        summary_frame = tk.Frame(result_frame, bg="#F5F7FA", relief="solid", bd=1)
        summary_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(summary_frame, text="📧 Gmail Scan Summary", bg="#F5F7FA", fg="#4632DA",
                 font=("Arial", 14, "bold")).pack(anchor="nw", pady=(10, 5))
        tk.Label(summary_frame, text=summary_text, bg="#F5F7FA", fg="black",
                 font=("Arial", 12), justify="left").pack(anchor="nw", pady=5)
        
        # Show detailed results
        if not display_df.empty:
            details_frame = tk.Frame(result_frame, bg="#F5F7FA")
            details_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            tk.Label(details_frame, text="🔍 Email Analysis Details", bg="#F5F7FA", fg="#4632DA", 
                     font=("Arial", 12, "bold")).pack(anchor="nw", pady=(0, 10))
            
            # Create scrollable frame for email details
            details_scroll_frame = create_scrollable_frame(details_frame)
            
            for idx, row in display_df.iterrows():
                cat = str(row["predicted"]).lower()
                color = color_map.get(cat, "black")
                subject = str(row["subject"])
                sender = str(row["sender"])
                body_preview = str(row["body"])[:100] + "..." if len(str(row["body"])) > 100 else str(row["body"])
                
                # Truncate long text
                subject_display = subject[:80] + ("..." if len(subject) > 80 else "")
                sender_display = sender[:60] + ("..." if len(sender) > 60 else "")
                
                # Create a frame for each email result
                email_result_frame = tk.Frame(details_scroll_frame, bg="white", relief="solid", bd=1)
                email_result_frame.pack(fill="x", padx=5, pady=5)
                
                # Email header
                header_frame = tk.Frame(email_result_frame, bg="white")
                header_frame.pack(fill="x", padx=10, pady=5)
                
                tk.Label(header_frame, text=f"📩 {subject_display}", bg="white", fg=color,
                         font=("Arial", 11, "bold"), justify="left", wraplength=800).pack(anchor="nw")
                tk.Label(header_frame, text=f"👤 From: {sender_display}", bg="white", fg="gray",
                         font=("Arial", 9), justify="left").pack(anchor="nw")
                
                # Email body preview
                if body_preview.strip():
                    body_frame = tk.Frame(email_result_frame, bg="white")
                    body_frame.pack(fill="x", padx=10, pady=(0, 5))
                    tk.Label(body_frame, text=f"📝 {body_preview}", bg="white", fg="darkgray",
                             font=("Arial", 9), justify="left", wraplength=800).pack(anchor="nw")
                
                # Classification result - FIXED: Show actual category
                result_frame_single = tk.Frame(email_result_frame, bg="white")
                result_frame_single.pack(fill="x", padx=10, pady=(0, 5))
                
                tk.Label(result_frame_single, text=f"🏷️ Classification: {cat.upper()}", 
                         bg="white", fg=color, font=("Arial", 10, "bold")).pack(side="left")
        
        # Update history and dashboard - IMPROVED VERSION
        for detail in email_details:
            history.append({
                "text": {  # Store as dictionary for richer data
                    "subject": detail["subject"],
                    "sender": detail["sender"],
                    "preview": detail["body"][:200] + "..." if detail["body"] and len(detail["body"]) > 200 else detail["body"],
                    "body": detail["body"],
                    "date": detail["date"]
                },
                "category": detail["category"],
                "type": "gmail",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    
        # Save history to file
        save_history(history)
    
        # Update last scanned email
        if not display_df.empty:
            last_scanned_email["text"] = display_df.iloc[0]["subject"] + ": " + (display_df.iloc[0]["body"][:100] + "..." if display_df.iloc[0]["body"] else "")
            last_scanned_email["category"] = display_df.iloc[0]["predicted"]
            save_last_scanned_email(last_scanned_email["text"], last_scanned_email["category"])
    
        mail.logout()
    
        # Show success message
        success_frame = tk.Frame(result_frame, bg="#F5F7FA")
        success_frame.pack(fill="x", padx=10, pady=10)
        tk.Label(success_frame, text="✅ Gmail scan completed successfully!", 
                 bg="#F5F7FA", fg="green", font=("Arial", 12, "bold")).pack(anchor="nw")
    
    except imaplib.IMAP4.error as e:
        error_msg = f"❌ Gmail Authentication Failed\n\nError: {str(e)}"
        if "Invalid credentials" in str(e) or "Authentication failed" in str(e):
            error_msg += "\n\n🔒 Please check your Gmail credentials and ensure:"
            error_msg += "\n• You're using the correct email address"
            error_msg += "\n• You're using an App Password (not your regular Gmail password)"
            error_msg += "\n• 2-Factor Authentication is enabled in your Google account"
            error_msg += "\n• You've generated an App Password for this application"
        
        error_frame = tk.Frame(result_frame, bg="#F5F7FA")
        error_frame.pack(fill="x", padx=10, pady=10)
        tk.Label(error_frame, text=error_msg, bg="#F5F7FA", fg="red",
                 font=("Arial", 11), justify="left", wraplength=800).pack(anchor="nw")
        
    except Exception as e:
        error_msg = f"❌ Error during Gmail scan: {str(e)}"
        error_frame = tk.Frame(result_frame, bg="#F5F7FA")
        error_frame.pack(fill="x", padx=10, pady=10)
        tk.Label(error_frame, text=error_msg, bg="#F5F7FA", fg="red",
                 font=("Arial", 11), justify="left", wraplength=800).pack(anchor="nw")
    
    progress.pack_forget()
    loading_label.pack_forget()
    
    # Add refresh button
    refresh_btn = tk.Button(result_frame, text="Refresh Scan", bg="#4632DA", fg="white", font=("Arial", 11, "bold"),
                           command=lambda: scan_gmail_emails(username, password, result_frame))
    refresh_btn.pack(pady=10)

# --- Email scanning UI with Gmail login ---
def build_email_scan_ui():
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()
    
    scan_label = tk.Label(main_content, text="Scan Emails", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    scan_label.pack(anchor="n", pady=(20, 10))
    
    # Create a notebook for tabs
    notebook = ttk.Notebook(main_content)
    notebook.pack(fill="both", expand=True, padx=20, pady=10)
    
    # Tab 1: Gmail Login & Scan
    gmail_frame = tk.Frame(notebook, bg="#F5F7FA")
    notebook.add(gmail_frame, text="Gmail Scan")
    
    # Tab 2: Single Email Analysis
    single_email_frame = tk.Frame(notebook, bg="#F5F7FA")
    notebook.add(single_email_frame, text="Single Email Analysis")
    
    # ===== GMAIL LOGIN TAB =====
    login_label = tk.Label(gmail_frame, text="Gmail Login Details", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    login_label.pack(anchor="n", pady=(30, 10))
    
    form_frame = tk.Frame(gmail_frame, bg="#F5F7FA")
    form_frame.place(relx=0.5, rely=0.3, anchor="center")
    
    tk.Label(form_frame, text="Gmail Address:", bg="#F5F7FA", font=("Arial", 11)).grid(row=0, column=0, sticky="w", pady=5)
    email_entry = tk.Entry(form_frame, width=30, font=("Arial", 11))
    email_entry.grid(row=0, column=1, padx=10, pady=5)
    
    tk.Label(form_frame, text="App Password:", bg="#F5F7FA", font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=5)
    pass_entry = tk.Entry(form_frame, width=30, show="*", font=("Arial", 11))
    pass_entry.grid(row=1, column=1, padx=10, pady=5)
    
    result_frame = tk.Frame(gmail_frame, bg="#F5F7FA")
    result_frame.pack(anchor="n", padx=10, pady=10, fill="x")
    
    def do_gmail_scan():
        username = email_entry.get().strip()
        password = pass_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both email and password")
            return
        
        login_label.pack_forget()
        form_frame.place_forget()
        
        # Pass the result_frame to the scan function
        scan_gmail_emails(username, password, result_frame)

    scan_btn = tk.Button(form_frame, text="Scan Gmail", command=do_gmail_scan, 
                        bg="#4632DA", fg="white", font=("Arial", 11, "bold"))
    scan_btn.grid(row=2, column=0, columnspan=2, pady=15)

    # ===== SINGLE EMAIL ANALYSIS TAB =====
    # Email input area
    input_frame = tk.Frame(single_email_frame, bg="#F5F7FA")
    input_frame.pack(fill="both", expand=True, padx=20, pady=10)

    tk.Label(input_frame, text="Enter Email Content:", bg="#F5F7FA", fg="#4632DA", 
             font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 5))

    # Email text area with scrollbar
    text_frame = tk.Frame(input_frame, bg="#F5F7FA")
    text_frame.pack(fill="both", expand=True, pady=5)

    email_text = tk.Text(text_frame, height=15, font=("Arial", 11), wrap="word")
    scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=email_text.yview)
    email_text.configure(yscrollcommand=scrollbar.set)

    email_text.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    # Example emails button
    def insert_example_email():
        examples = [
            """Congratulations! You've been selected as the winner of our $1,000,000 grand prize lottery! 
            This is a limited time offer that requires immediate action. To claim your prize, please click 
            on the following link: http://fake-lottery-claim.com/winner and provide your personal details.""",
            
            """Dear Valued Customer, Your Amazon order #ORD-7842-5519 has been successfully shipped via UPS. 
            The tracking number for your package is 1Z999AA10123456789. You can track your shipment at: 
            https://amazon.com/track/1Z999AA10123456789.""",
            
            """URGENT SECURITY ALERT: We have detected suspicious activity on your bank account. 
            Your account will be temporarily suspended within 24 hours unless you verify your identity. 
            Please click here immediately: http://secure-bank-verification-update.com""",
            
            """Hi John, I hope this email finds you well. I wanted to follow up on our conversation from last week 
            regarding the quarterly project review. The meeting is scheduled for tomorrow at 2:00 PM."""
        ]
        import random
        email_text.delete("1.0", tk.END)
        email_text.insert("1.0", random.choice(examples))

    example_btn = tk.Button(input_frame, text="Insert Example Email", bg="#4632DA", fg="white", 
                           font=("Arial", 10), command=insert_example_email)
    example_btn.pack(anchor="w", pady=5)

    # Analysis button
    def analyze_single_email():
        content = email_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Input Required", "Please enter email content to analyze.")
            return
        
        # Use the SAME classification as document upload
        category = classify_email(content)
        
        # Display results
        result_frame_single = tk.Frame(single_email_frame, bg="white", relief="solid", bd=1)
        result_frame_single.pack(fill="x", padx=20, pady=10)
        
        # Clear previous results
        for widget in result_frame_single.winfo_children():
            widget.destroy()
        
        # Color mapping (same as document upload)
        color_map = {"spam": "red", "scam": "orange", "ham": "green"}
        color = color_map.get(category.lower(), "black")
        
        # Result display
        tk.Label(result_frame_single, text="Analysis Result:", bg="white", fg="#4632DA", 
                font=("Arial", 13, "bold")).pack(anchor="w", pady=(10, 5))
        
        result_text = tk.Label(result_frame_single, text=f"Category: {category.upper()}", 
                              bg="white", fg=color, font=("Arial", 14, "bold"))
        result_text.pack(anchor="w", pady=5)
        
        # Save to history - IMPROVED VERSION
        history.append({
            "text": content[:500] + ("..." if len(content) > 500 else ""),
            "category": category,
            "type": "email", 
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_history(history)
        
        # Update last scanned email
        last_scanned_email["text"] = content[:500] + ("..." if len(content) > 500 else "")
        last_scanned_email["category"] = category
        save_last_scanned_email(last_scanned_email["text"], last_scanned_email["category"])

    analyze_btn = tk.Button(input_frame, text="Analyze Email", bg="#4632DA", fg="white",
                           font=("Arial", 12, "bold"), command=analyze_single_email)
    analyze_btn.pack(pady=10)

def build_sms_scan_ui():
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()
    
    # Create a main frame that will contain everything with scrollbar
    main_scroll_frame = tk.Frame(main_content, bg="#F5F7FA")
    main_scroll_frame.pack(fill="both", expand=True)
    
    # Create canvas and scrollbar for the main content
    canvas = tk.Canvas(main_scroll_frame, bg="#F5F7FA", highlightthickness=0)
    scrollbar = ttk.Scrollbar(main_scroll_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="#F5F7FA")
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack the canvas and scrollbar
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Bind mouse wheel to canvas
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    canvas.bind("<MouseWheel>", _on_mousewheel)
    scrollable_frame.bind("<MouseWheel>", _on_mousewheel)
    
    sms_label = tk.Label(scrollable_frame, text="SMS Scanning & Fraud Detection", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    sms_label.pack(anchor="n", pady=(20, 10))
    
    # Create a notebook for tabs
    notebook = ttk.Notebook(scrollable_frame)
    notebook.pack(fill="both", expand=True, padx=20, pady=10)
    
    # Tab 1: Vonage Configuration
    vonage_config_frame = tk.Frame(notebook, bg="#F5F7FA")
    notebook.add(vonage_config_frame, text="Vonage Setup")
    
    # Tab 2: Single SMS Analysis
    single_sms_frame = tk.Frame(notebook, bg="#F5F7FA")
    notebook.add(single_sms_frame, text="Single SMS Analysis")
    
    # Tab 3: SMS History
    sms_history_frame = tk.Frame(notebook, bg="#F5F7FA")
    notebook.add(sms_history_frame, text="SMS History")
    
    # ===== VONAGE CONFIGURATION TAB =====
    # Make Vonage config tab scrollable
    vonage_scroll_frame = create_scrollable_frame(vonage_config_frame)
    
    config_label = tk.Label(vonage_scroll_frame, text="Vonage Configuration", bg="#F5F7FA", fg="#4632DA", font=("Arial", 14, "bold"))
    config_label.pack(anchor="n", pady=(20, 10))
    
    config_form_frame = tk.Frame(vonage_scroll_frame, bg="#F5F7FA")
    config_form_frame.pack(fill="x", padx=20, pady=10)
    
    # API Key
    tk.Label(config_form_frame, text="API Key:", bg="#F5F7FA", font=("Arial", 11)).grid(row=0, column=0, sticky="w", pady=5)
    api_key_entry = tk.Entry(config_form_frame, width=40, font=("Arial", 11))
    api_key_entry.grid(row=0, column=1, padx=10, pady=5)
    api_key_entry.insert(0, vonage_config.get("api_key", ""))
    
    # API Secret
    tk.Label(config_form_frame, text="API Secret:", bg="#F5F7FA", font=("Arial", 11)).grid(row=1, column=0, sticky="w", pady=5)
    api_secret_entry = tk.Entry(config_form_frame, width=40, show="*", font=("Arial", 11))
    api_secret_entry.grid(row=1, column=1, padx=10, pady=5)
    api_secret_entry.insert(0, vonage_config.get("api_secret", ""))
    
    # Vonage Phone Number
    tk.Label(config_form_frame, text="Vonage Number:", bg="#F5F7FA", font=("Arial", 11)).grid(row=2, column=0, sticky="w", pady=5)
    phone_number_entry = tk.Entry(config_form_frame, width=40, font=("Arial", 11))
    phone_number_entry.grid(row=2, column=1, padx=10, pady=5)
    phone_number_entry.insert(0, vonage_config.get("phone_number", ""))
    
    # Webhook URL (display only)
    tk.Label(config_form_frame, text="Webhook URL:", bg="#F5F7FA", font=("Arial", 11)).grid(row=3, column=0, sticky="w", pady=5)
    webhook_url_label = tk.Label(config_form_frame, text=vonage_config.get("webhook_url", "Not configured"), 
                                bg="#F5F7FA", fg="blue", font=("Arial", 10), wraplength=300)
    webhook_url_label.grid(row=3, column=1, padx=10, pady=5, sticky="w")
    
    # Status label
    status_label = tk.Label(config_form_frame, text="", bg="#F5F7FA", fg="red", font=("Arial", 10))
    status_label.grid(row=4, column=0, columnspan=2, pady=10)
    
    def save_vonage_config_ui():
        api_key = api_key_entry.get().strip()
        api_secret = api_secret_entry.get().strip()
        phone_number = phone_number_entry.get().strip()
        
        if not api_key or not api_secret or not phone_number:
            status_label.config(text="❌ Please fill all fields", fg="red")
            return
        
        # Test Vonage credentials
        try:
            client = vonage.Client(key=api_key, secret=api_secret)
            sms = vonage.Sms(client)
            
            # Start webhook server and get URL
            webhook_url = start_vonage_webhook_server(api_key, api_secret, phone_number)
            
            # Save configuration
            vonage_config.update({
                "api_key": api_key,
                "api_secret": api_secret,
                "phone_number": phone_number,
                "webhook_url": webhook_url
            })
            save_vonage_config(vonage_config)
            
            webhook_url_label.config(text=webhook_url)
            status_label.config(text="✅ Vonage configured successfully! Webhook server running.", fg="green")
            
            # Show instructions for Vonage webhook setup
            show_vonage_instructions()
            
        except Exception as e:
            status_label.config(text=f"❌ Vonage authentication failed: {str(e)}", fg="red")
    
    def show_vonage_instructions():
        instructions_frame = tk.Frame(vonage_scroll_frame, bg="#F5F7FA")
        instructions_frame.pack(fill="x", padx=20, pady=20)
        
        instructions = """
📱 Vonage Webhook Setup Instructions:

1. Log in to your Vonage API dashboard
2. Go to Your Applications → [Your Application] → Settings
3. Find the "Webhooks" section
4. Set the "Inbound Message" webhook URL to: """ + vonage_config.get("webhook_url", "") + """
5. Set HTTP Method to: POST (or GET/POST if available)
6. Click "Save Changes"

Now your Vonage number will forward all incoming SMS to this application for fraud analysis!

Note: Vonage supports both GET and POST webhooks. The application handles both methods.
        """
        
        tk.Label(instructions_frame, text=instructions, bg="#F5F7FA", fg="black",
                font=("Arial", 10), justify="left").pack(anchor="w")
    
    save_btn = tk.Button(config_form_frame, text="Save & Start Webhook", command=save_vonage_config_ui,
                        bg="#4632DA", fg="white", font=("Arial", 11, "bold"))
    save_btn.grid(row=5, column=0, columnspan=2, pady=15)
    
    # Show instructions if already configured
    if vonage_config.get("api_key"):
        show_vonage_instructions()
    
    # ===== SINGLE SMS ANALYSIS TAB =====
    # Make Single SMS Analysis tab scrollable
    single_sms_scroll_frame = create_scrollable_frame(single_sms_frame)
    
    single_sms_label = tk.Label(single_sms_scroll_frame, text="Analyze Single SMS Message", bg="#F5F7FA", fg="#4632DA", font=("Arial", 14, "bold"))
    single_sms_label.pack(anchor="n", pady=(20, 10))
    
    # SMS input area
    sms_input_frame = tk.Frame(single_sms_scroll_frame, bg="#F5F7FA")
    sms_input_frame.pack(fill="both", expand=True, padx=20, pady=10)
    
    tk.Label(sms_input_frame, text="Enter SMS Content:", bg="#F5F7FA", fg="#4632DA", 
             font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 5))
    
    # SMS text area with scrollbar
    sms_text_frame = tk.Frame(sms_input_frame, bg="#F5F7FA")
    sms_text_frame.pack(fill="both", expand=True, pady=5)
    
    sms_text = tk.Text(sms_text_frame, height=10, font=("Arial", 11), wrap="word")
    sms_scrollbar = ttk.Scrollbar(sms_text_frame, orient="vertical", command=sms_text.yview)
    sms_text.configure(yscrollcommand=sms_scrollbar.set)
    
    sms_text.pack(side="left", fill="both", expand=True)
    sms_scrollbar.pack(side="right", fill="y")
    
    # Example SMS button
    def insert_example_sms():
        examples = [
            "Congratulations! You've won $5000 from Airtel! Click here to claim: http://bit.ly/win-airtel-now",
            "Your bank account has been suspended due to suspicious activity. Verify your identity immediately: https://secure-bank-verify.com",
            "URGENT: Your package delivery failed. Update your address here: http://track-package-delivery.com/update",
            "Hi mom, I need you to send me some money for groceries. Can you transfer $100?",
            "Amazon: Your order #12345 has shipped. Track at: https://amazon.com/track/1Z999AA1"
        ]
        import random
        sms_text.delete("1.0", tk.END)
        sms_text.insert("1.0", random.choice(examples))
    
    example_btn = tk.Button(sms_input_frame, text="Insert Example SMS", bg="#4632DA", fg="white", 
                           font=("Arial", 10), command=insert_example_sms)
    example_btn.pack(anchor="w", pady=5)
    
    # Analysis result frame
    sms_result_frame = tk.Frame(single_sms_scroll_frame, bg="#F5F7FA")
    sms_result_frame.pack(fill="x", padx=20, pady=10)
    
    def analyze_single_sms():
        content = sms_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Input Required", "Please enter SMS content to analyze.")
            return
        
        # Analyze for fraud
        fraud_result = analyze_sms_for_fraud(content, "Manual Input")
        
        # Display results
        for widget in sms_result_frame.winfo_children():
            widget.destroy()
        
        # Create a scrollable results container so long output is scrollable
        results_container = create_scrollable_frame(sms_result_frame)
        result_display_frame = tk.Frame(results_container, bg="white", relief="solid", bd=1)
        result_display_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Color mapping - use global COLOR_MAP
        color = COLOR_MAP.get(fraud_result['category'], "black")
        
        # Result display
        tk.Label(result_display_frame, text="SMS Analysis Result:", bg="white", fg="#4632DA", 
                font=("Arial", 13, "bold")).pack(anchor="w", pady=(10, 5))
        
        category_text = f"Category: {fraud_result['category'].upper()}"
        tk.Label(result_display_frame, text=category_text, bg="white", fg=color, 
                font=("Arial", 14, "bold")).pack(anchor="w", pady=5)
        
        confidence_text = f"Confidence Score: {fraud_result['confidence']:.2f}"
        tk.Label(result_display_frame, text=confidence_text, bg="white", fg="black",
                font=("Arial", 11)).pack(anchor="w", pady=2)
        
        # Show reasons if fraud detected
        if fraud_result['reasons']:
            reasons_frame = tk.Frame(result_display_frame, bg="white")
            reasons_frame.pack(fill="x", padx=5, pady=10)
            
            tk.Label(reasons_frame, text="Detection Reasons:", bg="white", fg="#4632DA",
                    font=("Arial", 11, "bold")).pack(anchor="w")
            
            for reason in fraud_result['reasons']:
                tk.Label(reasons_frame, text=f"• {reason}", bg="white", fg="black",
                        font=("Arial", 9), justify="left", wraplength=800).pack(anchor="w")
        
        # Save to history
        sms_history.append({
            "id": f"manual_{datetime.now().timestamp()}",
            "from_number": "Manual Input",
            "message": content,
            "category": fraud_result['category'],
            "confidence": fraud_result['confidence'],
            "reasons": fraud_result['reasons'],
            "timestamp": datetime.now().isoformat(),
            "is_fraud": fraud_result['is_fraud']
        })
        save_sms_history(sms_history)
        
        history.append({
            "text": f"SMS: {content[:100]}...",
            "category": fraud_result['category'],
            "type": "sms",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_history(history)

    analyze_btn = tk.Button(sms_input_frame, text="Analyze SMS", bg="#4632DA", fg="white",
                           font=("Arial", 12, "bold"), command=analyze_single_sms)
    analyze_btn.pack(pady=10)
    
    # ===== SMS HISTORY TAB =====
    # Make SMS History tab scrollable
    sms_history_scroll_frame = create_scrollable_frame(sms_history_frame)
    
    sms_history_label = tk.Label(sms_history_scroll_frame, text="SMS Analysis History", bg="#F5F7FA", fg="#4632DA", font=("Arial", 14, "bold"))
    sms_history_label.pack(anchor="n", pady=(20, 10))
    
    def refresh_sms_history():
        # Clear existing widgets in the history scroll frame
        for widget in sms_history_scroll_frame.winfo_children():
            if widget != sms_history_label:
                widget.destroy()
        
        if not sms_history:
            no_history_label = tk.Label(sms_history_scroll_frame, text="No SMS analysis history available", bg="#F5F7FA", fg="black", 
                                       font=("Arial", 12))
            no_history_label.pack(anchor="n", pady=20)
            return
        
        # Create scrollable frame for SMS history within the tab
        history_container = create_scrollable_frame(sms_history_scroll_frame)
        
        color_map = COLOR_MAP  # use global map
        
        for sms in reversed(sms_history[-50:]):  # Show last 50 items
            # defensive access with defaults for older/irregular entries
            category = str(sms.get("category", "")).lower()
            color = color_map.get(category, "black")
            from_number = sms.get("from_number") or sms.get("from") or sms.get("sender") or "Unknown"
            message_text = sms.get("message") or sms.get("text") or ""
            confidence = sms.get("confidence", 0.0)
            is_fraud = sms.get("is_fraud", False)
            ts_raw = sms.get("timestamp")
            try:
                timestamp = datetime.fromisoformat(ts_raw).strftime("%Y-%m-%d %H:%M:%S") if ts_raw else "Unknown"
            except Exception:
                # if not ISO format, fallback to string representation
                timestamp = str(ts_raw) if ts_raw else "Unknown"

            sms_item_frame = tk.Frame(history_container, bg="white", relief="solid", bd=1)
            sms_item_frame.pack(fill="x", padx=5, pady=5)

            # Header with number and timestamp
            header_frame = tk.Frame(sms_item_frame, bg="white")
            header_frame.pack(fill="x", padx=10, pady=5)

            tk.Label(header_frame, text=f"📱 From: {from_number}", bg="white", fg="black",
                    font=("Arial", 10, "bold")).pack(side="left")
            tk.Label(header_frame, text=f"🕒 {timestamp}", bg="white", fg="gray",
                    font=("Arial", 9)).pack(side="right")

            # Message content
            message_frame = tk.Frame(sms_item_frame, bg="white")
            message_frame.pack(fill="x", padx=10, pady=(0, 5))

            tk.Label(message_frame, text=message_text, bg="white", fg="black",
                    font=("Arial", 10), wraplength=800, justify="left").pack(anchor="w")

            # Analysis results
            result_frame = tk.Frame(sms_item_frame, bg="white")
            result_frame.pack(fill="x", padx=10, pady=(0, 5))

            category_text = f"Category: {category.upper() if category else 'UNKNOWN'}"
            tk.Label(result_frame, text=category_text, bg="white", fg=color,
                    font=("Arial", 10, "bold")).pack(side="left")

            confidence_text = f"Confidence: {confidence:.2f}" if isinstance(confidence, (int, float)) else f"Confidence: {confidence}"
            tk.Label(result_frame, text=confidence_text, bg="white", fg="gray",
                    font=("Arial", 9)).pack(side="left", padx=10)

            if is_fraud:
                tk.Label(result_frame, text="🚨 FRAUD DETECTED", bg="white", fg="red",
                        font=("Arial", 9, "bold")).pack(side="right")
    
    # Add refresh button
    refresh_btn = tk.Button(sms_history_scroll_frame, text="Refresh History", bg="#4632DA", fg="white",
                           font=("Arial", 10), command=refresh_sms_history)
    refresh_btn.pack(pady=10)
    
    # Initial load of SMS history
    refresh_sms_history()

def build_dashboard_ui():
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()
    
    dashboard_label = tk.Label(main_content, text="Dashboard", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    dashboard_label.pack(anchor="n", pady=(20, 10))
    
    # Display last scanned email
    if last_scanned_email["text"]:
        last_scan_frame = tk.Frame(main_content, bg="white", relief="solid", bd=1)
        last_scan_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Label(last_scan_frame, text="Last Scanned Email:", bg="white", fg="#4632DA", 
                font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        color_map = {"spam": "red", "scam": "orange", "ham": "green"}
        color = color_map.get(last_scanned_email["category"].lower(), "black")
        
        tk.Label(last_scan_frame, text=last_scanned_email["text"], bg="white", fg="black",
                font=("Arial", 10), wraplength=800, justify="left").pack(anchor="w", padx=10, pady=5)
        tk.Label(last_scan_frame, text=f"Category: {last_scanned_email['category'].upper()}", 
                bg="white", fg=color, font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(0, 10))
    
    # Quick actions
    actions_frame = tk.Frame(main_content, bg="#F5F7FA")
    actions_frame.pack(fill="x", padx=20, pady=20)
    
    tk.Label(actions_frame, text="Quick Actions:", bg="#F5F7FA", fg="#4632DA", 
            font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 10))
    
    action_buttons = [
        ("📧 Scan Emails", build_email_scan_ui),
        ("📱 Scan SMS", build_sms_scan_ui),
        ("📜 View History", build_history_ui),
        ("🎓 Training Module", build_training_ui)
    ]
    
    for text, command in action_buttons:
        btn = tk.Button(actions_frame, text=text, bg="#4632DA", fg="white", 
                       font=("Arial", 11, "bold"), command=command, width=20)
        btn.pack(side="left", padx=10, pady=5)

def build_history_ui():
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()
    
    history_label = tk.Label(main_content, text="Scan History", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    history_label.pack(anchor="n", pady=(20, 10))
    
    # Load the latest history (always refresh from disk)
    global history
    history = load_history()
    
    # Create summary frame
    summary_frame = tk.Frame(main_content, bg="#F5F7FA")
    summary_frame.pack(fill="x", padx=20, pady=10)
    
    # Calculate statistics
    total_scans = len(history)
    email_scans = len([h for h in history if h.get("type") in ["gmail", "email"]])
    sms_scans = len([h for h in history if h.get("type") == "sms"])
    manual_scans = len([h for h in history if h.get("type") in [None, "manual"]])
    
    category_counts = {}
    for item in history:
        cat = item.get("category", "unknown").lower()
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    summary_text = f"Total Scans: {total_scans} | Emails: {email_scans} | SMS: {sms_scans} | Manual: {manual_scans}"
    tk.Label(summary_frame, text=summary_text, bg="#F5F7FA", fg="#4632DA", 
             font=("Arial", 12, "bold")).pack(anchor="w")
    
    # Category breakdown
    if category_counts:
        category_text = " | ".join([f"{k.upper()}: {v}" for k, v in category_counts.items()])
        tk.Label(summary_frame, text=category_text, bg="#F5F7FA", fg="#667085", 
                font=("Arial", 10)).pack(anchor="w", pady=(5, 0))
    
    # Selection management
    selected_items = set()
    
    def toggle_selection(item_index, checkbox_var):
        if checkbox_var.get():
            selected_items.add(item_index)
        else:
            selected_items.discard(item_index)
        
        # Update delete button state
        if selected_items:
            delete_selected_btn.config(state="normal", text=f"Delete Selected ({len(selected_items)})")
        else:
            delete_selected_btn.config(state="disabled", text="Delete Selected")
    
    # Action buttons frame
    action_frame = tk.Frame(main_content, bg="#F5F7FA")
    action_frame.pack(fill="x", padx=20, pady=10)
    
    # Select All checkbox
    select_all_var = tk.BooleanVar()
    
    def toggle_select_all():
        if select_all_var.get():
            # Select all visible items
            for idx in range(len(display_history)):
                selected_items.add(idx)
                checkbox_vars[idx].set(True)
        else:
            # Deselect all
            selected_items.clear()
            for var in checkbox_vars:
                var.set(False)
        
        # Update delete button
        if selected_items:
            delete_selected_btn.config(state="normal", text=f"Delete Selected ({len(selected_items)})")
        else:
            delete_selected_btn.config(state="disabled", text="Delete Selected")
    
    select_all_cb = tk.Checkbutton(action_frame, text="Select All", variable=select_all_var,
                                  bg="#F5F7FA", command=toggle_select_all)
    select_all_cb.pack(side="left", padx=5)
    
    # Delete selected button
    def delete_selected_items():
        if not selected_items:
            return
            
        result = messagebox.askyesno(
            "Confirm Deletion", 
            f"Are you sure you want to delete {len(selected_items)} selected item(s)?"
        )
        
        if result:
            global history
            
            # Convert selected indices to actual history indices
            indices_to_delete = []
            for display_idx in selected_items:
                if display_idx < len(display_history):
                    # Find the actual item in the full history
                    item_to_delete = display_history[display_idx]
                    for i, hist_item in enumerate(history):
                        if hist_item == item_to_delete:
                            indices_to_delete.append(i)
                            break
            
            # Remove items from history (from highest to lowest index to maintain order)
            for index in sorted(indices_to_delete, reverse=True):
                if index < len(history):
                    history.pop(index)
            
            save_history(history)
            selected_items.clear()
            select_all_var.set(False)
            
            # Refresh the display
            refresh_history_display()
            messagebox.showinfo("Success", f"Deleted {len(indices_to_delete)} item(s) successfully!")
    
    delete_selected_btn = tk.Button(action_frame, text="Delete Selected", bg="#D93B3B", fg="white",
                                   font=("Arial", 10), state="disabled", command=delete_selected_items)
    delete_selected_btn.pack(side="left", padx=5)
    
    # Clear all button
    def clear_all_history():
        result = messagebox.askyesno("Clear History", "Are you sure you want to clear ALL history? This cannot be undone.")
        if result:
            global history
            history = []
            save_history(history)
            selected_items.clear()
            select_all_var.set(False)
            refresh_history_display()
            messagebox.showinfo("Success", "All history cleared successfully!")
    
    clear_all_btn = tk.Button(action_frame, text="Clear All History", bg="#D93B3B", fg="white",
                             font=("Arial", 10), command=clear_all_history)
    clear_all_btn.pack(side="left", padx=5)
    
    # Add filter options
    filter_frame = tk.Frame(main_content, bg="#F5F7FA")
    filter_frame.pack(fill="x", padx=20, pady=10)
    
    tk.Label(filter_frame, text="Filter by:", bg="#F5F7FA", fg="#4632DA", 
             font=("Arial", 11, "bold")).pack(side="left")
    
    filter_var = tk.StringVar(value="all")
    
    filter_options = [
        ("All", "all"),
        ("Gmail", "gmail"),
        ("Email", "email"),
        ("SMS", "sms"),
        ("Spam", "spam"),
        ("Scam", "scam"),
        ("Ham", "ham")
    ]
    
    for text, value in filter_options:
        rb = tk.Radiobutton(filter_frame, text=text, variable=filter_var, value=value,
                           bg="#F5F7FA", command=lambda: refresh_history_display())
        rb.pack(side="left", padx=5)
    
    # Create scrollable frame for history
    history_container = tk.Frame(main_content, bg="#F5F7FA")
    history_container.pack(fill="both", expand=True, padx=20, pady=10)
    
    # Create canvas and scrollbar
    canvas = tk.Canvas(history_container, bg="#F5F7FA", highlightthickness=0)
    scrollbar = ttk.Scrollbar(history_container, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="#F5F7FA")
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Bind mouse wheel to canvas
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    canvas.bind("<MouseWheel>", _on_mousewheel)
    
    # Color map for categories
    color_map = {"spam": "red", "scam": "orange", "ham": "green", "unknown": "gray"}
    
    # Global variables for display
    display_history = []
    checkbox_vars = []
    
    def refresh_history_display():
        """Refresh the history display based on current filter"""
        nonlocal display_history, checkbox_vars
        
        # Clear existing widgets
        for widget in scrollable_frame.winfo_children():
            widget.destroy()
        
        # Reset selection
        selected_items.clear()
        select_all_var.set(False)
        checkbox_vars = []
        delete_selected_btn.config(state="disabled", text="Delete Selected")
        
        current_filter = filter_var.get()
        
        # Filter history based on selection
        filtered_history = []
        for item in reversed(history):  # Show newest first
            if current_filter == "all":
                filtered_history.append(item)
            elif current_filter in ["gmail", "email", "sms"]:
                if item.get("type") == current_filter:
                    filtered_history.append(item)
            elif current_filter in ["spam", "scam", "ham"]:
                if item.get("category", "").lower() == current_filter:
                    filtered_history.append(item)
        
        # Limit display to prevent memory issues
        display_history = filtered_history[:100]  # Show max 100 items
        
        if not display_history:
            no_results_label = tk.Label(scrollable_frame, text="No items match the current filter", 
                                       bg="#F5F7FA", fg="black", font=("Arial", 12))
            no_results_label.pack(pady=20)
            return
        
        for idx, item in enumerate(display_history):
            color = color_map.get(item.get("category", "").lower(), "black")
            
            # Create checkbox for selection
            checkbox_var = tk.BooleanVar()
            checkbox_vars.append(checkbox_var)
            
            # Create a frame for each history item with checkbox
            history_item_frame = tk.Frame(scrollable_frame, bg="white", relief="solid", bd=1)
            history_item_frame.pack(fill="x", padx=5, pady=2)
            
            # Top row with checkbox and type badge
            top_frame = tk.Frame(history_item_frame, bg="white")
            top_frame.pack(fill="x", padx=8, pady=4)
            
            # Checkbox for selection
            checkbox = tk.Checkbutton(top_frame, variable=checkbox_var, bg="white",
                                    command=lambda idx=idx, var=checkbox_var: toggle_selection(idx, var))
            checkbox.pack(side="left")
            
            # Type badge
            item_type = item.get("type", "manual")
            type_color = {"gmail": "#4632DA", "email": "#4632DA", "sms": "#4C9F70", "manual": "#667085"}.get(item_type, "#667085")
            
            type_label = tk.Label(top_frame, text=item_type.upper(), bg=color, fg="white",
                                 font=("Arial", 8, "bold"), padx=4, pady=1)
            type_label.pack(side="left", padx=(5, 0))
            
            # Timestamp
            timestamp = item.get("timestamp", "Unknown time")
            timestamp_label = tk.Label(top_frame, text=timestamp, bg="white", fg="gray",
                                      font=("Arial", 8))
            timestamp_label.pack(side="right")
            
            # Content
            content_frame = tk.Frame(history_item_frame, bg="white")
            content_frame.pack(fill="x", padx=8, pady=2)
            
            text_content = item.get("text", "No content")
            
            # Handle both string and dictionary formats
            if isinstance(text_content, dict):
                # If it's a dictionary from Gmail scan
                subject = text_content.get("subject", "No subject")
                sender = text_content.get("sender", "Unknown sender")
                preview = text_content.get("preview", "")
                display_text = f"From: {sender} | Subject: {subject}"
                
                if preview:
                    display_text += f" | Preview: {preview[:50]}..."
            else:
                # Regular string content - truncate to prevent long text
                display_text = text_content[:150] + "..." if len(text_content) > 150 else text_content
            
            content_label = tk.Label(content_frame, text=display_text, bg="white", fg="black",
                                    font=("Arial", 9), wraplength=600, justify="left")
            content_label.pack(anchor="w")
            
            # Category and actions
            footer_frame = tk.Frame(history_item_frame, bg="white")
            footer_frame.pack(fill="x", padx=8, pady=2)
            
            category = item.get("category", "unknown").upper()
            category_label = tk.Label(footer_frame, text=f"Category: {category}", 
                                    bg="white", fg=color, font=("Arial", 9, "bold"))
            category_label.pack(side="left")
            
            # Add a view details button only for Gmail items
            if item.get("type") == "gmail" and isinstance(text_content, dict):
                def view_details(content_dict=text_content, cat=category):
                    show_email_details(content_dict, cat)
                
                details_btn = tk.Button(footer_frame, text="View", bg="#4632DA", fg="white",
                                       font=("Arial", 7), command=view_details)
                details_btn.pack(side="right", padx=2)
        
        # Update the scroll region
        canvas.configure(scrollregion=canvas.bbox("all"))
    
    # Initial display
    refresh_history_display()

def build_training_ui():
    """
    User Training Simulation Module (Multiple Choice Questions)
    - Presents cybersecurity scenarios as multiple-choice questions
    - Provides instant feedback and explanations
    - Tracks user progress and scores
    """
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()

    # UI layout
    title = tk.Label(main_content, text="🎓 Cybersecurity Awareness Training", bg="#F5F7FA",
                     fg="#4632DA", font=("Arial", 16, "bold"))
    title.pack(anchor="n", pady=(20, 8))

    instr = tk.Label(main_content, 
                     text="Test your cybersecurity knowledge! Read each scenario and choose the best answer.\nLearn to identify phishing emails, scam SMS, and other cyber threats.",
                     bg="#F5F7FA", fg="#333", font=("Arial", 10), justify="center")
    instr.pack(anchor="n", pady=(0,10))

    # Score and progress display
    score_frame = tk.Frame(main_content, bg="#F5F7FA")
    score_frame.pack(fill="x", padx=20, pady=(0,10))
    
    score_label = tk.Label(score_frame, text="Score: 0/0", bg="#F5F7FA", fg="#4632DA", 
                          font=("Arial", 12, "bold"))
    score_label.pack(side="left")
    
    progress_label = tk.Label(score_frame, text="Progress: 0%", bg="#F5F7FA", fg="#667085",
                             font=("Arial", 10))
    progress_label.pack(side="right")

    # Question area
    q_frame = tk.Frame(main_content, bg="white", relief="solid", bd=1)
    q_frame.pack(fill="both", expand=True, padx=20, pady=10)

    # Question number and scenario type
    q_header_frame = tk.Frame(q_frame, bg="white")
    q_header_frame.pack(fill="x", padx=10, pady=(10,5))
    
    q_number = tk.Label(q_header_frame, text="Question 1/7", bg="white", fg="#4632DA", 
                       font=("Arial", 12, "bold"))
    q_number.pack(side="left")
    
    q_type = tk.Label(q_header_frame, text="[Email Scenario]", bg="white", fg="#667085", 
                     font=("Arial", 10))
    q_type.pack(side="right")

    # Question text
    q_text = tk.Text(q_frame, height=8, wrap="word", font=("Arial", 11), bg="white", 
                    relief="flat", padx=10, pady=10)
    q_text.pack(fill="both", expand=True)

    # Options area
    options_frame = tk.Frame(q_frame, bg="#F5F7FA")
    options_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))

    option_var = tk.StringVar()

    def create_option_button(index, text):
        btn_frame = tk.Frame(options_frame, bg="#F5F7FA")
        btn_frame.pack(fill="x", pady=2)
        
        radio = tk.Radiobutton(btn_frame, variable=option_var, value=str(index), 
                              bg="#F5F7FA", anchor="w", command=lambda: submit_btn.config(state="normal"))
        radio.pack(side="left")
        
        label = tk.Label(btn_frame, text=text, bg="#F5F7FA", fg="#333", 
                        font=("Arial", 10), justify="left", wraplength=800, anchor="w")
        label.pack(side="left", fill="x", expand=True, padx=5)
        
        return radio, label

    # Create 4 option buttons
    option_buttons = []
    option_texts = []
    for i in range(4):
        radio, label = create_option_button(i, f"Option {i+1}")
        option_buttons.append(radio)
        option_texts.append(label)

    # Feedback area
    feedback_frame = tk.Frame(main_content, bg="#F5F7FA")
    feedback_frame.pack(fill="x", padx=20, pady=5)
    
    feedback_text = tk.Text(feedback_frame, height=4, wrap="word", font=("Arial", 10), 
                           bg="#F5F7FA", fg="#333", relief="flat")
    feedback_text.pack(fill="x", padx=5)
    feedback_text.config(state="disabled")

    # Navigation buttons
    nav_frame = tk.Frame(main_content, bg="#F5F7FA")
    nav_frame.pack(fill="x", padx=20, pady=10)

    prev_btn = tk.Button(nav_frame, text="◀ Previous", bg="#667085", fg="white",
                        font=("Arial", 10), state="disabled")
    prev_btn.pack(side="left", padx=5)

    submit_btn = tk.Button(nav_frame, text="Submit Answer", bg="#4632DA", fg="white",
                          font=("Arial", 11, "bold"), state="disabled")
    submit_btn.pack(side="left", padx=5)

    next_btn = tk.Button(nav_frame, text="Next ▶", bg="#4C9F70", fg="white",
                        font=("Arial", 10), state="disabled")
    next_btn.pack(side="left", padx=5)

    restart_btn = tk.Button(nav_frame, text="Restart Training", bg="#D93B3B", fg="white",
                           font=("Arial", 10))
    restart_btn.pack(side="right", padx=5)

    # ===== CYBERSECURITY TRAINING QUESTIONS =====
    training_questions = [
        {
            "type": "Email",
            "question": "You receive an email that says: 'URGENT: Your bank account will be suspended in 24 hours! Click here to verify your identity: http://secure-bank-verification.com'. The sender address is 'security@zanaco-verify.com'. What should you do?",
            "options": [
                "Click the link immediately to secure your account",
                "Forward the email to friends to warn them",
                "Delete the email - it's likely a phishing attempt",
                "Reply to the email asking for more information"
            ],
            "correct": 2,
            "explanation": "✅ CORRECT! This is a classic phishing attempt. It uses urgency ('URGENT'), threats (account suspension), and a suspicious link. Legitimate banks use official domains (@zanaco.co.zm) and don't ask for verification via email links."
        },
        {
            "type": "SMS",
            "question": "You get an SMS: 'Congratulations! You've won K5000 from Airtel! Click here to claim your prize: bit.ly/win-airtel'. What is the safest action?",
            "options": [
                "Click the link to see if you really won",
                "Forward the SMS to family members",
                "Ignore and delete the message immediately",
                "Call the number provided to verify"
            ],
            "correct": 2,
            "explanation": "✅ CORRECT! This is a lottery scam SMS ('smishing'). Legitimate companies don't award prizes via random SMS links. Never click suspicious links in messages."
        },
        {
            "type": "Password",
            "question": "Which of these is the MOST secure password practice?",
            "options": [
                "Using your pet's name followed by your birth year",
                "Using the same strong password for all your accounts",
                "Using a password manager with unique, complex passwords",
                "Writing down passwords in a notebook kept near your computer"
            ],
            "correct": 2,
            "explanation": "✅ CORRECT! Password managers generate and store unique, complex passwords for each account, protecting you from credential stuffing attacks where hackers use leaked passwords on multiple sites."
        },
        {
            "type": "Email",
            "question": "An email from 'Amazon' says your order #ORD-12345 has shipping issues and needs address confirmation. It looks professional with Amazon logos. What should you check FIRST?",
            "options": [
                "The tracking number in the email",
                "The sender's email address carefully",
                "Your Amazon app or website directly",
                "The order details in the email"
            ],
            "correct": 2,
            "explanation": "✅ CORRECT! Always go directly to the official website or app instead of clicking links in emails. Scammers create convincing fake emails, but they can't access your actual account on the real site."
        },
        {
            "type": "Social Engineering",
            "question": "You receive a call from someone claiming to be from 'Microsoft Support' saying your computer has viruses. They ask for remote access to 'fix' it. What do you do?",
            "options": [
                "Give them remote access since they're from Microsoft",
                "Ask for their employee ID and call back using Microsoft's official number",
                "Follow their instructions to protect your computer",
                "Provide your computer details for their analysis"
            ],
            "correct": 1,
            "explanation": "✅ CORRECT! This is a common tech support scam. Microsoft doesn't make unsolicited calls about viruses. Always verify by calling official numbers from the company's website, not numbers provided by the caller."
        },
        {
            "type": "Wi-Fi",
            "question": "You're at a coffee shop and see two Wi-Fi networks: 'CoffeeShop-Free' and 'CoffeeShop-Guest'. Which is safer to use?",
            "options": [
                "CoffeeShop-Free - it's more convenient",
                "CoffeeShop-Guest - it's probably the official one",
                "Ask the staff which network is legitimate",
                "Use your phone's mobile data instead"
            ],
            "correct": 2,
            "explanation": "✅ CORRECT! Always verify the official network name with staff. Hackers create fake Wi-Fi networks with similar names to steal your data. When in doubt, use mobile data for sensitive activities."
        },
        {
            "type": "Two-Factor",
            "question": "You receive a login verification code via SMS, but you're not trying to log in anywhere. What does this likely mean?",
            "options": [
                "The system sent it by mistake - ignore it",
                "Someone has your password and is trying to access your account",
                "It's a promotional message from the service",
                "Your account is automatically updating"
            ],
            "correct": 1,
            "explanation": "✅ CORRECT! Unsolicited verification codes mean someone has your password and is trying to log in. Immediately change your password for that service and enable two-factor authentication if not already active."
        }
    ]

    # Internal state
    current_question = 0
    user_score = 0
    user_answers = [None] * len(training_questions)
    quiz_completed = False

    def update_display():
        """Update the question display"""
        nonlocal quiz_completed
        
        if quiz_completed:
            show_results()
            return
            
        q_data = training_questions[current_question]
        
        # Update question info
        q_number.config(text=f"Question {current_question + 1}/{len(training_questions)}")
        q_type.config(text=f"[{q_data['type']} Scenario]")
        
        # Update question text
        q_text.config(state="normal")
        q_text.delete("1.0", tk.END)
        q_text.insert("1.0", q_data["question"])
        q_text.config(state="disabled")
        
        # Update options
        for i, option_text in enumerate(option_texts):
            option_text.config(text=q_data["options"][i])
        
        # Clear selection and feedback
        option_var.set("")
        feedback_text.config(state="normal")
        feedback_text.delete("1.0", tk.END)
        feedback_text.config(state="disabled")
        
        # Update button states
        prev_btn.config(state="normal" if current_question > 0 else "disabled")
        submit_btn.config(state="disabled")
        next_btn.config(state="disabled")
        
        # If user already answered this question, show their answer
        if user_answers[current_question] is not None:
            option_var.set(str(user_answers[current_question]))
            submit_btn.config(state="disabled")
            next_btn.config(state="normal")
            show_feedback()
        
        update_score_display()

    def update_score_display():
        """Update score and progress"""
        answered = sum(1 for ans in user_answers if ans is not None)
        progress = (answered / len(training_questions)) * 100
        
        score_label.config(text=f"Score: {user_score}/{answered}")
        progress_label.config(text=f"Progress: {progress:.0f}%")

    def show_feedback():
        """Show feedback for the current question"""
        q_data = training_questions[current_question]
        user_answer = user_answers[current_question]
        
        feedback_text.config(state="normal")
        feedback_text.delete("1.0", tk.END)
        
        if user_answer is not None:
            if user_answer == q_data["correct"]:
                feedback_text.insert("1.0", q_data["explanation"])
                feedback_text.config(bg="#E6F4EA", fg="#0D652D")  # Green background
            else:
                correct_answer = q_data["options"][q_data["correct"]]
                feedback_text.insert("1.0", 
                    f"❌ Not quite right. The correct answer is: {correct_answer}\n\n"
                    f"{q_data['explanation']}"
                )
                feedback_text.config(bg="#FCE8E6", fg="#C5221F")  # Red background
        
        feedback_text.config(state="disabled")

    def submit_answer():
        """Submit the selected answer"""
        if not option_var.get():
            return
            
        user_answer = int(option_var.get())
        user_answers[current_question] = user_answer
        
        # Check if correct
        if user_answer == training_questions[current_question]["correct"]:
            nonlocal user_score
            user_score += 1
        
        submit_btn.config(state="disabled")
        next_btn.config(state="normal")
        show_feedback()
        update_score_display()

    def next_question():
        """Move to next question"""
        nonlocal current_question, quiz_completed
        
        if current_question < len(training_questions) - 1:
            current_question += 1
            update_display()
        else:
            quiz_completed = True
            update_display()

    def previous_question():
        """Move to previous question"""
        nonlocal current_question
        if current_question > 0:
            current_question -= 1
            update_display()

    def restart_quiz():
        """Restart the training"""
        nonlocal current_question, user_score, user_answers, quiz_completed
        current_question = 0
        user_score = 0
        user_answers = [None] * len(training_questions)
        quiz_completed = False
        update_display()

    def show_results():
        """Show final results"""
        for widget in [q_frame, options_frame, feedback_frame]:
            widget.pack_forget()
        
        results_frame = tk.Frame(main_content, bg="white", relief="solid", bd=1)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        percentage = (user_score / len(training_questions)) * 100
        
        # Result message based on score
        if percentage >= 80:
            result_text = "🎉 Excellent! You're a Cybersecurity Expert!"
            color = "#0D652D"
            bg_color = "#E6F4EA"
        elif percentage >= 60:
            result_text = "👍 Good Job! You have solid cybersecurity knowledge!"
            color = "#1E6BD5"
            bg_color = "#E8F0FE"
        else:
            result_text = "📚 Keep Learning! Review the training materials."
            color = "#C5221F"
            bg_color = "#FCE8E6"
        
        results_frame.config(bg=bg_color)
        
        tk.Label(results_frame, text="Training Complete!", bg=bg_color, fg=color,
                font=("Arial", 16, "bold")).pack(pady=(20, 10))
        
        tk.Label(results_frame, text=result_text, bg=bg_color, fg=color,
                font=("Arial", 14)).pack(pady=5)
        
        tk.Label(results_frame, text=f"Final Score: {user_score}/{len(training_questions)} ({percentage:.0f}%)", 
                bg=bg_color, fg=color, font=("Arial", 12, "bold")).pack(pady=10)
        
        # Review incorrect answers
        if user_score < len(training_questions):
            review_frame = tk.Frame(results_frame, bg=bg_color)
            review_frame.pack(fill="x", padx=20, pady=10)
            
            tk.Label(review_frame, text="Review these areas:", bg=bg_color, fg=color,
                    font=("Arial", 11, "bold")).pack(anchor="w")
            
            for i, (q, user_ans) in enumerate(zip(training_questions, user_answers)):
                if user_ans != q["correct"]:
                    review_text = f"• Question {i+1}: {q['type']} scenario"
                    tk.Label(review_frame, text=review_text, bg=bg_color, fg="#5F6368",
                            font=("Arial", 9), justify="left").pack(anchor="w", padx=10)

    # Connect buttons to functions
    submit_btn.config(command=submit_answer)
    next_btn.config(command=next_question)
    prev_btn.config(command=previous_question)
    restart_btn.config(command=restart_quiz)

    # Start the quiz
    update_display()

def build_profile_ui():
    cancel_history_refresh()
    for widget in main_content.winfo_children():
        widget.destroy()
    
    profile_label = tk.Label(main_content, text="User Profile", bg="#F5F7FA", fg="#4632DA", font=("Arial", 16, "bold"))
    profile_label.pack(anchor="n", pady=(20, 10))
    
    profile_frame = tk.Frame(main_content, bg="white", relief="solid", bd=1)
    profile_frame.pack(fill="x", padx=20, pady=10)
    
    profile_info = [
        ("Name:", "User"),
        ("Email:", "user@example.com"),
        ("Member Since:", "2024"),
        ("Total Scans:", str(len(history)))
    ]
    
    for label, value in profile_info:
        row_frame = tk.Frame(profile_frame, bg="white")
        row_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(row_frame, text=label, bg="white", fg="#4632DA", font=("Arial", 11, "bold"), 
                width=15, anchor="w").pack(side="left")
        tk.Label(row_frame, text=value, bg="white", fg="black", font=("Arial", 11)).pack(side="left")

# Main app window
root = tk.Tk()
root.title("Zamsafe Detection System")
root.geometry("1000x600")
root.config(bg="#F5F7FA")

# Top navigation bar
top_bar = tk.Frame(root, bg="#4632DA", height=40)
top_bar.pack(side="top", fill="x")

title = tk.Label(top_bar, text="Zamsafe Detection System", bg="#4632DA", fg="white", font=("Arial", 12, "bold"))
title.pack(side="left", padx=10)

def restart_program():
    import os
    import sys
    os.execv(sys.executable, ['python'] + sys.argv)

refresh_app_btn = tk.Button(top_bar, text="Refresh", bg="#4632DA", fg="white", font=("Arial", 10, "bold"),
                            command=restart_program)
refresh_app_btn.pack(side="left", padx=10)

# Sidebar
sidebar = tk.Frame(root, bg="white", width=220)
sidebar.pack(side="left", fill="y")

# Sidebar items
menu_items = [
    ("📊  Dashboard",),
    ("📧  Scan Emails",),
    ("📱  Scan SMS",),
    ("📜  History",),
    ("🎓  User Training Simulation Module",)
]

# Create sidebar buttons
for item in menu_items:
    if item[0] == "📧  Scan Emails":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_email_scan_ui)
    elif item[0] == "📊  Dashboard":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_dashboard_ui)
    elif item[0] == "📜  History":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_history_ui)
    elif item[0] == "🎓  User Training Simulation Module":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_training_ui)
    elif item[0] == "📱  Scan SMS":
        btn = tk.Button(sidebar, text=item[0], font=("Arial", 11), anchor="w",
                        bg="white", fg="#333", relief="flat", padx=15, pady=10,
                        command=build_sms_scan_ui)
    btn.pack(fill="x")

# Add profile section at bottom of sidebar
profile_frame = tk.Frame(sidebar, bg="white")
profile_frame.pack(side="bottom", fill="x", pady=10)

# Main content area
main_content = tk.Frame(root, bg="#F5F7FA")
main_content.pack(side="left", expand=True, fill="both")

# Show the dashboard by default when the app starts
build_dashboard_ui()

# Install required packages reminder
def check_dependencies():
    try:
        import vonage
        from flask import Flask
    except ImportError:
        print("⚠️  Required packages not installed. Please run:")
        print("pip install vonage flask")
        messagebox.showwarning("Dependencies Missing", 
                             "Vonage and Flask packages are required for SMS functionality.\n\n"
                             "Please run: pip install vonage flask")

check_dependencies()

root.mainloop()       ]rrrf