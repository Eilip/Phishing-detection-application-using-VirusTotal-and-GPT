import tkinter as tk
from tkinter import scrolledtext
import time
import requests
import json
from datetime import datetime
from tkinter import simpledialog
import socket
import os

# Function to create sus.js and blacklist.js files if not exist
def create_files():
    if not os.path.exists("sus.js"):
        with open("sus.js", "w") as sus_file:
            sus_file.write("[]")
    if not os.path.exists("blacklist.js"):
        with open("blacklist.js", "w") as blacklist_file:
            blacklist_file.write("[]")

# Function for Virustotal API scanning
def scan_link(link):
    api_key = "VIRUSTOTAL API_KEYS"  # Replace with your Virustotal API key
    url = f"https://www.virustotal.com/vtapi/v2/url/scan"
    params = {"apikey": api_key, "url": link}

    try:
        response = requests.post(url, data=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in scan_link: {e}")
        return None

# Function to get Virustotal scan report
def get_scan_report(scan_id):
    api_key = "VIRUSTOTAL API_KEY"  # Replace with your Virustotal API key
    url = f"https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": scan_id}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in get_scan_report: {e}")
        return None

# Function for ChatGPT API
def chatgpt_api(prompt):
    openai_key = "GPT_API_keys"  # Replace with your OpenAI API key
    endpoint = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {openai_key}",
    }

    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}],
    }

    try:
        response = requests.post(endpoint, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        print(f"Error in chatgpt_api: {e}")
        return None

# Function to find server IP address
def find_server_ip(link):
    try:
        ip_address = socket.gethostbyname(link)
        return ip_address
    except socket.error as e:
        print(f"Error in finding server IP: {e}")
        return None
    
    
def clear_entries():
    entry_link.delete(0, tk.END)
    entry_email.delete(0, tk.END)
    output_entry.delete(1.0, tk.END)

# Function to log entry in the database
def log_entry(filename, link, email, date_time, api_issue=False, gpt_issue=False):
    server_ip = find_server_ip(link)

    entry = {
        "link": link,
        "email": email,
        "date_time": date_time,
        "api_issue": api_issue,
        "gpt_issue": gpt_issue,
        "server_ip": server_ip  # Add server IP to the log
    }

    with open(filename, "r") as file:
        data = json.load(file)

    data.append(entry)

    with open(filename, "w") as file:
        json.dump(data, file, indent=2)

# Function to input email for attacker
def input_email(message):
    email_sender = tk.simpledialog.askstring("Email Input", message)
    return email_sender

# Function to process the scan result
def process_scan_result(link, email, date_time, scan_result):
    if scan_result.get("positives", 0) > 0:
        output_entry.insert(tk.END, "Dangerous link! Please enter the email of the sender.\n", "danger")
        email_sender = input_email("Enter the email of the sender:")
        log_entry("blacklist.js", link, email_sender, date_time)
    else:
        output_entry.insert(tk.END, "VirusTotal: Good, now scanning with GPT...\n")
        gpt_response = chatgpt_api(f"Given the URL {link}, please evaluate its properties and classify it:\n" \
            "- 'good' if the URL is from a well-known and trusted source like https://google.com, https://facebook.com, or https://eilipkarki.com.np or https://abc.com\n" \
            "- 'bad' if the URL exhibits suspicious characteristics such as a similar name to a known service, insecure protocol, or deceptive practices.\n" \
            "- 'sus' if the URL has an insecure pathway or employs tactics commonly associated with hacking like '@' or redirection using and does not fall in the good category'//'.\n\n"
            "Consider aspects like the domain, protocol, and overall structure of the URL. and just provide classification as a single-word reply.")
        gpt_response = f"GPT: {gpt_response}\n"
        output_entry.insert(tk.END, gpt_response, "gpt")

        if "bad" in gpt_response or "sus" in gpt_response:
            email_sender = input_email("Enter the email of the sender:")
            log_entry("sus.js" if "sus" in gpt_response else "blacklist.js", link, email_sender, date_time)

# Main process function
def main_process():
    link = entry_link.get()
    email = entry_email.get()
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    output_entry.insert(tk.END, "Scanning in VirusTotal...\n")
    scan_result = scan_link(link)

    if scan_result:
        scan_id = scan_result.get("scan_id")
        if scan_id:
            time.sleep(5)
            process_scan_result(link, email, date_time, get_scan_report(scan_id))
        else:
            output_entry.insert(tk.END, "Invalid response from VirusTotal API\n", "danger")
            log_entry("sus.js", link, email, date_time, api_issue=True)
    else:
        output_entry.insert(tk.END, "Error in VirusTotal scan\n", "danger")
        log_entry("sus.js", link, email, date_time, api_issue=True)

# Create tkinter window
root = tk.Tk()
root.title("Eilip's Anti-Phishing Tool")
root.geometry("1056x599")

# Create files if not exist
create_files()

# Load background image
background_image = tk.PhotoImage(file="pic1.png")
background_label = tk.Label(root, image=background_image)
background_label.place(relwidth=1, relheight=1)

# Create labels and entry widgets
label_link = tk.Label(root, text="Enter Link:")
label_link.place(x=20, y=20)
entry_link = tk.Entry(root, width=80, background='silver')
entry_link.place(x=100, y=20)


label_email = tk.Label(root, text="Enter Email:")
label_email.place(x=20, y=60)
entry_email = tk.Entry(root, width=40 , background='silver')
entry_email.place(x=100, y=60)

# Create scrolled text widget for output
output_entry = scrolledtext.ScrolledText(root, width=70, height=15, background='grey', fg='white',  wrap=tk.WORD)
output_entry.place(x=20, y=100)

# Create Scan Link button
button_scan = tk.Button(root, text="Scan Link", background="yellow", fg='red', command=main_process)
button_scan.place(x=20, y=350)

# Create Clear button
button_clear = tk.Button(root, text="Clear", background="red", fg='yellow', command=clear_entries)
button_clear.place(x=120, y=350)

# Define tag configuration for styling output
output_entry.tag_configure("danger", foreground="red")
output_entry.tag_configure("gpt", foreground="blue")
output_entry.tag_configure("gpt", foreground="blue")

root.mainloop()
