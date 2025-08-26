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

for item in menu_items:
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
