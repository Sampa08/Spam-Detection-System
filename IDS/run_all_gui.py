import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from main import IDSController

# queue for messages from IDS thread -> GUI
msg_queue = queue.Queue()

def ids_notify(msg, msg_type="info", payload=None):
    # push a small dict into queue
    msg_queue.put({"msg": msg, "type": msg_type, "payload": payload or {}})

def run_ids(duration=60):
    controller = IDSController()
    # start realtime monitoring; it will call ids_notify for updates
    controller.start_realtime_monitoring(duration=duration, notify=ids_notify)

# --- GUI ---
root = tk.Tk()
root.title("IDS GUI")
root.geometry("900x600")

# Top controls
ctrl_frame = tk.Frame(root)
ctrl_frame.pack(fill="x", padx=8, pady=6)

duration_var = tk.IntVar(value=60)
tk.Label(ctrl_frame, text="Duration (s):").pack(side="left")
tk.Entry(ctrl_frame, width=6, textvariable=duration_var).pack(side="left", padx=6)

start_btn = tk.Button(ctrl_frame, text="Start IDS")
stop_btn = tk.Button(ctrl_frame, text="Stop IDS", state="disabled")

start_btn.pack(side="left", padx=6)
stop_btn.pack(side="left")

# Left: Alerts list
alerts_frame = tk.LabelFrame(root, text="Alerts", width=300)
alerts_frame.pack(side="left", fill="y", padx=8, pady=6)
alerts_list = tk.Listbox(alerts_frame, width=40, height=30)
alerts_list.pack(side="left", fill="both", expand=True)
alerts_scroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=alerts_list.yview)
alerts_scroll.pack(side="right", fill="y")
alerts_list.config(yscrollcommand=alerts_scroll.set)

# Right: Log / progress
log_frame = tk.LabelFrame(root, text="IDS Log")
log_frame.pack(side="right", fill="both", expand=True, padx=8, pady=6)
log_text = scrolledtext.ScrolledText(log_frame, wrap="word", state="disabled", height=30)
log_text.pack(fill="both", expand=True)

ids_thread = None
ids_controller = None
stop_event = threading.Event()

def append_log(text):
    log_text.config(state="normal")
    log_text.insert("end", text + "\n")
    log_text.see("end")
    log_text.config(state="disabled")

def process_queue():
    try:
        while True:
            item = msg_queue.get_nowait()
            m = item.get("msg", "")
            t = item.get("type", "info")
            payload = item.get("payload", {})
            if t == "alert":
                display = f"{payload.get('timestamp', '')} {payload.get('alert_type','ALERT')} - {payload.get('src_ip','?')} -> {payload.get('dst_ip','?')}"
                alerts_list.insert("end", display)
                append_log(f"[ALERT] {m} | {payload}")
            elif t == "progress":
                append_log(f"[PROGRESS] {m}")
            else:
                append_log(f"[INFO] {m}")
    except queue.Empty:
        pass
    root.after(200, process_queue)

def start_ids_btn():
    global ids_thread, stop_event
    if ids_thread and ids_thread.is_alive():
        messagebox.showinfo("Already running","IDS is already running")
        return
    stop_event.clear()
    duration = duration_var.get()
    ids_thread = threading.Thread(target=run_ids, args=(duration,), daemon=True)
    ids_thread.start()
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    append_log("Started IDS thread")

def stop_ids_btn():
    # no direct stop available — user can Ctrl+C on console or we could add stop support in IDSController
    append_log("Stop requested. (If implemented, IDSController.stop would be called.)")
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

start_btn.config(command=start_ids_btn)
stop_btn.config(command=stop_ids_btn)

# start queue polling
root.after(200, process_queue)
root.mainloop()