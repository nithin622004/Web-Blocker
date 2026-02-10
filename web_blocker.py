import tkinter as tk
from tkinter import messagebox, simpledialog
import getpass
import platform
import os
import subprocess
from datetime import datetime, timedelta
import threading
import time
from collections import defaultdict

# -----------------------------
# Configuration / Globals
# -----------------------------
redirect = "127.0.0.1"

if platform.system() == "Windows":
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
else:
    hosts_path = "/etc/hosts"

current_user = getpass.getuser()
user_file = f"blocked_sites_{current_user}.txt"
log_file = f"blocked_log_{current_user}.txt"

APP_PASSWORD = "admin123"  # Change to your desired password

scheduled_blocks = []
temporary_blocks = []

font_name = "Roboto"
placeholder_text = "Enter websites separated by commas..."

# -----------------------------
# AI Configuration
# -----------------------------
AI_CATEGORIES = {
    "Social Media": ["facebook.com", "instagram.com", "twitter.com", "tiktok.com", "reddit.com"],
    "Streaming/Video": ["youtube.com", "netflix.com", "hulu.com", "disneyplus.com"],
    "Gaming": ["twitch.tv", "steamcommunity.com", "epicgames.com"],
    "News Overload": ["cnn.com", "foxnews.com", "theguardian.com"]
}

AI_SUGGESTION_DAYS = 7
AI_SUGGESTION_THRESHOLD = 5

# -----------------------------
# Helper Functions
# -----------------------------
def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def check_password():
    pwd = simpledialog.askstring("Password", "Enter Password:", show="*")
    if pwd != APP_PASSWORD:
        messagebox.showerror("Access Denied", "Incorrect password!")
        root.destroy()
        exit()

def load_blocked_sites():
    listbox.delete(0, tk.END)
    try:
        with open(hosts_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith(redirect):
                    parts = line.split()
                    if len(parts) > 1:
                        site = parts[1]
                        if not site.startswith("www."):
                            listbox.insert(tk.END, site)
        count = listbox.size()
        count_label.config(text=f"{count} site{'s' if count != 1 else ''} blocked")
    except PermissionError:
        # This error is now handled at startup by is_admin(), but kept as a fallback.
        messagebox.showerror("Permission Denied", "Run as Administrator to view blocked sites.")
    except FileNotFoundError:
        # Create the hosts file if it doesn't exist (rare, but good practice)
        with open(hosts_path, 'w') as f:
            pass
        load_blocked_sites()

def log_action(action, sites):
    try:
        clean_sites = [s.replace("www.", "") for s in sites]
        unique_sites = sorted(list(set(clean_sites)))
        with open(log_file, "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {action}: {', '.join(unique_sites)}\n")
    except Exception:
        pass

def flush_dns():
    try:
        if platform.system() == "Windows":
            subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
        elif platform.system() == "Darwin":
            subprocess.run("sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder", shell=True, capture_output=True)
        else:
            subprocess.run("sudo systemd-resolve --flush-caches", shell=True, capture_output=True)
        messagebox.showinfo("DNS Flushed", "DNS cache has been successfully flushed.")
    except Exception:
        messagebox.showwarning("Failed", "Could not flush DNS. Run with administrator privileges.")

def write_to_hosts(sites_to_block):
    try:
        with open(hosts_path, 'r+') as file:
            content = file.read()
            if not content.endswith('\n') and content != "":
                file.write('\n')
            for s in sites_to_block:
                if s not in content:
                    file.write(f"{redirect} {s}\n")
    except PermissionError:
        messagebox.showerror("Permission Denied", "Run as Administrator to modify the hosts file.")
        return False
    return True

def remove_from_hosts(sites_to_unblock):
    try:
        with open(hosts_path, 'r') as file:
            lines = file.readlines()
        with open(hosts_path, 'w') as file:
            for line in lines:
                if not any(f"{redirect} {s}" in line.strip() for s in sites_to_unblock):
                    file.write(line)
    except PermissionError:
        messagebox.showerror("Permission Denied", "Run as Administrator to modify the hosts file.")
        return False
    return True

# -----------------------------
# Main Functionalities
# -----------------------------
def block_website():
    input_sites = entry.get().strip()
    if input_sites and input_sites != placeholder_text:
        sites = [s.strip().replace("www.", "") for s in input_sites.split(",")]
        sites_to_block = []
        for s in sites:
            if s:
                sites_to_block.extend([s, "www." + s])
        sites_to_block = list(set(sites_to_block))

        if write_to_hosts(sites_to_block):
            log_action("Blocked", sites)
            load_blocked_sites()
            messagebox.showinfo("Blocked", f"Successfully blocked: {', '.join(sites)}")
            on_entry_leave(None) # Clears the entry box
    else:
        messagebox.showerror("Error", "Please enter at least one website URL.")

def unblock_website(site=None):
    if site is None:
        input_sites = entry.get().strip()
        if not input_sites or input_sites == placeholder_text:
            messagebox.showerror("Error", "Please enter a website URL to unblock.")
            return
        sites = [s.strip().replace("www.", "") for s in input_sites.split(",")]
    else:
        sites = [site.replace("www.", "")]
    
    sites_to_unblock = []
    for s in sites:
       if s:
            sites_to_unblock.extend([s, "www." + s])
    sites_to_unblock = list(set(sites_to_unblock))

    if remove_from_hosts(sites_to_unblock):
        log_action("Unblocked", sites)
        load_blocked_sites()
        messagebox.showinfo("Unblocked", f"Successfully unblocked: {', '.join(sites)}")
        on_entry_leave(None) # Clears the entry box

def listbox_double_click(event):
    selection = listbox.curselection()
    if selection:
        site = listbox.get(selection[0])
        if messagebox.askyesno("Confirm Unblock", f"Are you sure you want to unblock '{site}'?"):
            unblock_website(site)

# -----------------------------
# AI/Category Block & Unblock Functionality
# -----------------------------
def category_block():
    category = category_var.get()
    if category in AI_CATEGORIES:
        sites_to_block = AI_CATEGORIES[category]
        sites_string = ", ".join(sites_to_block)
        
        # Pre-fill the entry box and then call the main block function
        entry.delete(0, tk.END)
        entry.insert(0, sites_string)
        entry.config(fg="#F0F6FC")
        
        block_website()
        log_action(f"AI Block ({category})", sites_to_block)
    else:
        messagebox.showerror("AI Error", "Please select an AI category to block.")

def unblock_category():
    category = category_var.get()
    if category in AI_CATEGORIES:
        sites_to_unblock_base = AI_CATEGORIES[category]
        
        sites_to_unblock_hosts = []
        for site in sites_to_unblock_base:
            sites_to_unblock_hosts.extend([site, f"www.{site}"])

        if remove_from_hosts(sites_to_unblock_hosts):
            log_action(f"AI Unblock ({category})", sites_to_unblock_base)
            load_blocked_sites()
            messagebox.showinfo("Category Unblocked", f"The '{category}' category has been unblocked.")
    else:
        messagebox.showerror("AI Error", "Please select an AI category to unblock.")

# -----------------------------
# AI LOG ANALYSIS (Intelligent Suggestion)
# -----------------------------
def analyze_user_patterns():
    if not os.path.exists(log_file):
        return

    now = datetime.now()
    time_limit = now - timedelta(days=AI_SUGGESTION_DAYS)
    block_counts = defaultdict(int)

    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    timestamp_str, rest = line.split(" - ", 1)
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                    if timestamp > time_limit:
                        action, sites_str = rest.split(": ", 1)
                        if action == "Blocked":
                            sites = [s.strip() for s in sites_str.split(',')]
                            for site in sites:
                                if site and not site.startswith("www."):
                                    block_counts[site] += 1
                except ValueError:
                    continue
    except Exception:
        return

    currently_blocked = [s.replace("www.","") for s in listbox.get(0, tk.END)]
    sorted_sites = sorted(block_counts.items(), key=lambda item: item[1], reverse=True)

    for site, count in sorted_sites:
        if count > AI_SUGGESTION_THRESHOLD and site not in currently_blocked:
            if messagebox.askyesno("🧠 AI Productivity Suggestion",
                                   f"AI noticed you blocked '{site}' {count} times recently.\n\n"
                                   f"Block it now to improve your focus?"):
                entry.delete(0, tk.END)
                entry.insert(0, site)
                entry.config(fg="#F0F6FC")
                block_website()
                log_action("AI Suggestion Block", [site])
            return # Only show one suggestion at a time

# -----------------------------
# Scheduled / Temporary Blocks
# -----------------------------
def schedule_block():
    input_sites = entry.get().strip()
    if not input_sites or input_sites == placeholder_text:
        messagebox.showerror("Error", "Enter at least one website to schedule.")
        return
    start_time_str = simpledialog.askstring("Schedule Start", "Enter start time (HH:MM, 24hr format)")
    end_time_str = simpledialog.askstring("Schedule End", "Enter end time (HH:MM, 24hr format)")
    if not start_time_str or not end_time_str:
        return
    try:
        start_time = datetime.strptime(start_time_str, "%H:%M").time()
        end_time = datetime.strptime(end_time_str, "%H:%M").time()
        sites = [s.strip().replace("www.", "") for s in input_sites.split(",")]
        sites = [s for s in sites if s]
        scheduled_blocks.append((sites, start_time, end_time))
        messagebox.showinfo("Scheduled", f"Scheduled block for {', '.join(sites)} from {start_time_str} to {end_time_str}.")
        log_action("Scheduled Block", sites)
    except ValueError:
        messagebox.showerror("Error", "Invalid time format. Please use HH:MM 24hr format.")

def temporary_block():
    input_sites = entry.get().strip()
    if not input_sites or input_sites == placeholder_text:
        messagebox.showerror("Error", "Enter at least one website for a temporary block.")
        return
    duration_str = simpledialog.askstring("Temporary Block", "Enter duration in minutes:")
    try:
        duration = int(duration_str)
        if duration <= 0:
            raise ValueError
        sites = [s.strip().replace("www.", "") for s in input_sites.split(",")]
        sites = [s for s in sites if s]
        end_time = datetime.now() + timedelta(minutes=duration)
        temporary_blocks.append((sites, end_time))
        
        sites_to_block_hosts = [s for site in sites for s in (site, "www." + site)]
        if write_to_hosts(sites_to_block_hosts):
            log_action("Temporary Block", sites)
            messagebox.showinfo("Temporary Block", f"Blocked {', '.join(sites)} for {duration} minutes.")
            load_blocked_sites()
    except (ValueError, TypeError):
        messagebox.showerror("Error", "Please enter a valid positive number for minutes.")

# --- NEW, CORRECTED SCHEDULER FUNCTION ---
def background_scheduler():
    ai_check_interval = 900
    last_ai_check = time.time() - ai_check_interval

    while True:
        now_time = datetime.now().time()
        now_datetime = datetime.now()

        # --- START: REVISED SCHEDULING LOGIC ---
        
        sites_to_block_now = set()
        all_scheduled_sites = set()

        # 1. Determine which scheduled sites should be active right now
        for sites, start, end in scheduled_blocks:
            all_scheduled_sites.update(sites)
            
            # Check if the schedule is currently active, correctly handling overnight schedules
            is_active = False
            if start < end:  # Normal same-day schedule (e.g., 09:00-17:00)
                if start <= now_time < end:
                    is_active = True
            else:  # Overnight schedule (e.g., 22:00-07:00)
                if now_time >= start or now_time < end:
                    is_active = True

            if is_active:
                sites_to_block_now.update(sites)

        # 2. Determine which scheduled sites to unblock
        # These are sites that are part of a schedule but not an active one
        sites_to_unblock_from_schedule = all_scheduled_sites - sites_to_block_now
        
        # 3. Apply the changes
        if sites_to_unblock_from_schedule:
            sites_to_unblock_hosts = {s for site in sites_to_unblock_from_schedule for s in (site, f"www.{site}")}
            remove_from_hosts(list(sites_to_unblock_hosts))

        if sites_to_block_now:
            sites_to_block_hosts = {s for site in sites_to_block_now for s in (site, f"www.{site}")}
            write_to_hosts(list(sites_to_block_hosts))

        # --- END: REVISED SCHEDULING LOGIC ---

        # Temporary block logic
        for tb in temporary_blocks[:]:
            sites, end_time = tb
            if now_datetime >= end_time:
                # Ensure we don't unblock a site that is still under an active schedule
                sites_still_scheduled = [s for s in sites if s in sites_to_block_now]
                sites_to_unblock_temp = [s for s in sites if s not in sites_still_scheduled]

                if sites_to_unblock_temp:
                    sites_to_unblock_hosts_temp = [s for site in sites_to_unblock_temp for s in (site, "www." + site)]
                    remove_from_hosts(sites_to_unblock_hosts_temp)
                    log_action("Temp Block Expired", sites_to_unblock_temp)
                
                temporary_blocks.remove(tb)
                root.after(0, load_blocked_sites)
        
        # AI check logic
        if time.time() - last_ai_check > ai_check_interval:
            root.after(0, analyze_user_patterns)
            last_ai_check = time.time()
            
        time.sleep(30)


# -----------------------------
# GUI Setup
# -----------------------------
root = tk.Tk()
root.title("Professional Website Blocker")
root.geometry("900x800")
root.resizable(False, False)
root.configure(bg="#1A1D23")

# --- MODIFIED STARTUP LOGIC ---
if not is_admin():
    messagebox.showerror("Administrator Rights Required", 
                         "This application modifies the system hosts file and requires administrator privileges to run.\n\nPlease restart the application as an administrator.")
    root.destroy()
else:
    root.withdraw()
    check_password()
    root.deiconify()

    main_container = tk.Frame(root, bg="#1A1D23")
    main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=25)

    header_frame = tk.Frame(main_container, bg="#1A1D23")
    header_frame.pack(fill=tk.X, pady=(0, 20))

    title_label = tk.Label(header_frame, text="🛡 Website Blocker Pro 🧠", font=(font_name, 26, "bold"), bg="#1A1D23", fg="#FFFFFF")
    title_label.pack()

    user_label = tk.Label(header_frame, text=f"Active User: {current_user}", font=(font_name, 12), bg="#1A1D23", fg="#8B949E")
    user_label.pack(pady=(8, 0))

    separator = tk.Frame(main_container, height=2, bg="#30363D")
    separator.pack(fill=tk.X, pady=(0, 20))

    input_section = tk.Frame(main_container, bg="#1A1D23")
    input_section.pack(fill=tk.X, pady=(0, 20))

    input_label = tk.Label(input_section, text="🌐 Enter Website URLs to Block/Unblock:", font=(font_name, 13, "bold"), bg="#1A1D23", fg="#F0F6FC")
    input_label.pack(anchor=tk.W, pady=(0, 8))

    entry_container = tk.Frame(input_section, bg="#21262D", relief=tk.SOLID, bd=1)
    entry_container.pack(fill=tk.X, pady=(0, 8))

    entry = tk.Entry(entry_container, font=(font_name, 13), bg="#21262D", fg="#F0F6FC", insertbackground="#58A6FF", bd=0, relief=tk.FLAT)
    entry.pack(fill=tk.X, padx=15, pady=12)

    def on_entry_click(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg="#F0F6FC")

    def on_entry_leave(event):
        if not entry.get():
            entry.insert(0, placeholder_text)
            entry.config(fg="#8B949E")

    entry.insert(0, placeholder_text)
    entry.config(fg="#8B949E")
    entry.bind("<FocusIn>", on_entry_click)
    entry.bind("<FocusOut>", on_entry_leave)

    help_label = tk.Label(input_section, text="💡 Example: facebook.com, youtube.com, instagram.com", font=(font_name, 10), bg="#1A1D23", fg="#8B949E")
    help_label.pack(anchor=tk.W)

    buttons_section = tk.Frame(main_container, bg="#1A1D23")
    buttons_section.pack(fill=tk.X, pady=(0, 15))

    def create_professional_button(parent, text, bg_color, hover_color, command, width=18):
        btn = tk.Button(parent, text=text, font=(font_name, 11, "bold"), bg=bg_color, fg="#FFFFFF", command=command, relief=tk.FLAT, bd=0, padx=15, pady=10, width=width, cursor="hand2")
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_color))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg_color))
        return btn

    primary_frame = tk.Frame(buttons_section, bg="#1A1D23")
    primary_frame.pack(pady=(0, 15))

    block_btn = create_professional_button(primary_frame, "🚫 Block Websites", "#DC3545", "#C82333", block_website)
    block_btn.pack(side=tk.LEFT, padx=(0, 10))

    unblock_btn = create_professional_button(primary_frame, "✅ Unblock Websites", "#28A745", "#218838", lambda: unblock_website())
    unblock_btn.pack(side=tk.LEFT, padx=(10, 0))

    secondary_container = tk.Frame(buttons_section, bg="#1A1D23")
    secondary_container.pack(pady=(15, 0))

    ai_frame = tk.LabelFrame(secondary_container, text=" AI Controls ", font=(font_name, 12, "bold"), bg="#1A1D23", fg="#58A6FF", padx=15, pady=10, relief=tk.GROOVE, bd=2)
    ai_frame.pack(pady=(0, 15))

    category_var = tk.StringVar(ai_frame)
    category_var.set("Select Category")
    category_options = ["Select Category"] + list(AI_CATEGORIES.keys())
    category_menu = tk.OptionMenu(ai_frame, category_var, *category_options)
    category_menu.config(font=(font_name, 10), bg="#30363D", fg="#F0F6FC", relief=tk.FLAT, bd=0, activebackground="#58A6FF", width=15, direction="below")
    category_menu["menu"].config(bg="#30363D", fg="#F0F6FC", activebackground="#58A6FF")
    category_menu.pack(side=tk.LEFT, padx=(0, 10))

    ai_block_btn = create_professional_button(ai_frame, "🔥 Block Category", "#6610F2", "#520BAF", category_block, width=16)
    ai_block_btn.pack(side=tk.LEFT)

    ai_unblock_btn = create_professional_button(ai_frame, "🔓 Unblock Category", "#28A745", "#218838", unblock_category, width=16)
    ai_unblock_btn.pack(side=tk.LEFT, padx=(10, 0))

    utility_frame = tk.LabelFrame(secondary_container, text=" Utilities ", font=(font_name, 12, "bold"), bg="#1A1D23", fg="#FD7E14", padx=15, pady=10, relief=tk.GROOVE, bd=2)
    utility_frame.pack()

    schedule_btn = create_professional_button(utility_frame, "📅 Schedule Block", "#FD7E14", "#E8630A", schedule_block, width=14)
    schedule_btn.pack(side=tk.LEFT, padx=(0,10))

    temp_btn = create_professional_button(utility_frame, "⏰ Temporary Block", "#6F42C1", "#5A2D91", temporary_block, width=14)
    temp_btn.pack(side=tk.LEFT, padx=(0,10))

    flush_btn = create_professional_button(utility_frame, "🔄 Flush DNS", "#0D6EFD", "#0B5ED7", flush_dns, width=14)
    flush_btn.pack(side=tk.LEFT)

    sites_section = tk.Frame(main_container, bg="#1A1D23")
    sites_section.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

    sites_header = tk.Frame(sites_section, bg="#1A1D23")
    sites_header.pack(fill=tk.X, pady=(0, 12))

    sites_title = tk.Label(sites_header, text="📋 Currently Blocked Websites", font=(font_name, 15, "bold"), bg="#1A1D23", fg="#F0F6FC")
    sites_title.pack(side=tk.LEFT)

    count_label = tk.Label(sites_header, text="0 sites blocked", font=(font_name, 12, "bold"), bg="#1A1D23", fg="#FD7E14")
    count_label.pack(side=tk.RIGHT)

    list_container = tk.Frame(sites_section, bg="#30363D", relief=tk.SOLID, bd=2)
    list_container.pack(fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(list_container)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = tk.Listbox(list_container, font=(font_name, 12), bg="#21262D", fg="#F0F6FC", selectbackground="#0D6EFD", selectforeground="#FFFFFF", yscrollcommand=scrollbar.set, bd=0, relief=tk.FLAT, activestyle='none', highlightthickness=0)
    listbox.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
    scrollbar.config(command=listbox.yview)

    listbox.bind("<Double-Button-1>", listbox_double_click)

    instructions = tk.Label(sites_section, text="💡 Double-click any website in the list to unblock it instantly.", font=(font_name, 11), bg="#1A1D23", fg="#8B949E")
    instructions.pack(pady=(10,0), anchor='w')

    load_blocked_sites()

    scheduler_thread = threading.Thread(target=background_scheduler, daemon=True)
    scheduler_thread.start()

    root.mainloop()
