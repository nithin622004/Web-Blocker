# desktop-web-blocker

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

A cross-platform (Windows, macOS, Linux) desktop application with a modern UI to help you block distracting websites and boost your productivity. This tool uses your system's `hosts` file for effective blocking and includes smart features like category-based blocking, scheduling, and AI-powered suggestions.



## 🌟 Core Features

* **Administrator Required**: Automatically checks for admin/sudo privileges, which are necessary to modify the `hosts` file.
* **Password Protected**: The application is locked with a hardcoded password for simple access control.
* **Block & Unblock**: Manually add or remove one or more comma-separated websites.
* **Live Blocked List**: A scrollable list shows all websites currently blocked by the application.
* **Quick Unblock**: Instantly unblock any site by double-clicking its name in the list.
* **AI Category Block**: Block entire categories of sites (e.g., "Social Media", "Streaming/Video") with a single click.
* **Scheduled Blocking**: Set a start and end time (in 24-hour HH:MM format) to automatically block sites during specific hours (e.g., your work-day). Correctly handles overnight schedules.
* **Temporary "Focus" Block**: Block sites for a specific duration (in minutes) to start an immediate focus session.
* **🧠 Smart Productivity AI**:
    * Analyzes your blocking history from a local log file.
    * If it notices you've manually blocked the same site multiple times recently (e.g., >5 times in 7 days), it will proactively pop up a suggestion to block it for you, helping you identify and curb your most common distractions.
* **DNS Flusher**: A built-in utility button to flush your system's DNS cache, ensuring block/unblock changes take effect immediately.
* **Cross-Platform**: Designed to work on Windows, macOS, and Linux.

## 📦 Dependencies

This script is self-contained and has **no external dependencies**. It uses only Python's built-in libraries, primarily `tkinter` for the GUI and standard modules like `os`, `platform`, and `threading`.

## 🚀 How to Use

1.  **Run as Administrator (Crucial!)**
    * This program modifies the system `hosts` file, which requires elevated privileges.
    * **On Windows**: Right-click the `.py` or `.exe` file and select "Run as administrator".
    * **On macOS/Linux**: Run the script from your terminal using `sudo`:
        ```bash
        sudo python3 app.py
        ```

2.  **Enter Password**
    * On launch, you will be prompted for a password.
    * The default password is: **`admin123`** (You can change this in the code).

3.  **Use the Interface**
    * **Manual**: Enter sites like `google.com, reddit.com` in the text box and click "Block" or "Unblock".
    * **AI Category**: Select a category (e.g., "Social Media") from the dropdown and click "Block Category" or "Unblock Category".
    * **Scheduling**: Enter sites, click "Schedule Block", and enter a start/end time (e.g., `09:00` and `17:00`).
    * **Temporary**: Enter sites, click "Temporary Block", and enter the duration in minutes (e.g., `45`).

## ⚙️ Configuration

You can easily customize the application by editing the global variables at the top of the Python script:

```python
# -----------------------------
# Configuration / Globals
# -----------------------------
redirect = "127.0.0.1"

if platform.system() == "Windows":
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
else:
    hosts_path = "/etc/hosts"

# --- CHANGE THIS ---
APP_PASSWORD = "admin123"  # Change to your desired password

# --- ADD/EDIT CATEGORIES ---
AI_CATEGORIES = {
    "Social Media": ["facebook.com", "instagram.com", "twitter.com", "tiktok.com", "reddit.com"],
    "Streaming/Video": ["youtube.com", "netflix.com", "hulu.com", "disneyplus.com"],
    "Gaming": ["twitch.tv", "steamcommunity.com", "epicgames.com"],
    "News Overload": ["cnn.com", "foxnews.com", "theguardian.com"]
}

# --- TWEAK AI SUGGESTIONS ---
AI_SUGGESTION_DAYS = 7       # How many days back the AI should look
AI_SUGGESTION_THRESHOLD = 5  # How many times a site must be blocked to trigger a suggestion
