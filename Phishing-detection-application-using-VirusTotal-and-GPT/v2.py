import tkinter as tk
from tkinter import scrolledtext
import time
import requests
import json
from datetime import datetime
from urllib.parse import urlparse
from tkinter import simpledialog
import socket

def scan_link(link):
    api_key = "YOUR_VIRUSTOTAL_API_KEY"
    url = f"https://www.virustotal.com/vtapi/v2/url/scan"
    params = {"apikey": api_key, "url": link}

    try:
        response = requests.post(url, data=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in scan_link: {e}")
        return None

def get_scan_report(scan_id):
    api_key = "YOUR_VIRUSTOTAL_API_KEY"
    url = f"https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": scan_id}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in get_scan_report: {e}")
        return None

def chatgpt_api(prompt):
    # Replace with your actual OpenAI API key
    openai_key = "YOUR_OPENAI_API_KEY"
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

def find_server_ip(link):
    try:
        ip_address = socket.gethostbyname(link)
        return ip_address
    except socket.error as e:
        print(f"Error in finding server IP: {e}")
        return None

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

def input_email(message):
    email_sender = tk.simpledialog.askstring("Email Input", message)
    return email_sender

def process_scan_result(link, email, date_time, scan_result):
    if scan_result.get("positives", 0) > 0:
        output_entry.insert(tk.END, "Dangerous link! Please enter the email of the sender.\n")
        email_sender = input_email("Enter the email of the sender:")
        log_entry("blacklist.js", link, email_sender, date_time)
    else:
        gpt_result = chatgpt_api(f'Here {link} is a URL. Provide a single-word response:\n'
                                 '- "good" if the URL is from google.com, facebook.com, or abc.com.\n'
                                 '- "bad" if the URL has a suspiciously similar name or insecure protocol.\n'
                                 '- "sus" if the URL has an insecure pathway or uses hacking tactics.')
        if gpt_result == "good":
            output_entry.insert(tk.END, "You can go to the link.\n")
        elif gpt_result == "bad":
            output_entry.insert(tk.END, "Bad link! Please enter the email of the sender.\n")
            email_sender = input_email("Enter the email of the sender:")
            log_entry("blacklist.js", link, email_sender, date_time)
        elif gpt_result == "sus":
            output_entry.insert(tk.END, "Suspicious link! Please enter the email of the sender.\n")
            email_sender = input_email("Enter the email of the sender:")
            log_entry("sus.js", link, email_sender, date_time)
        else:
            output_entry.insert(tk.END, "GPT not working. Please enter the email of the sender.\n")
            log_entry("sus.js", link, email, date_time, gpt_issue=True)

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
            output_entry.insert(tk.END, "VirusTotal scanning done... Now using GPT to analyze.\n")
            result = get_scan_report(scan_id)

            # Added IP finder function
            server_ip = find_server_ip(link)
            output_entry.insert(tk.END, f"Server IP Address: {server_ip}\n")

            process_scan_result(link, email, date_time, result)
        else:
            output_entry.insert(tk.END, "Invalid response from VirusTotal API\n")
            log_entry("sus.js", link, email, date_time, api_issue=True)
    else:
        output_entry.insert(tk.END, "Error in VirusTotal scan\n")
        log_entry("sus.js", link, email, date_time, api_issue=True)

root = tk.Tk()
root.title("Eilip's Anti-Phishing Tool")
root.geometry("800x400")

background_image = tk.PhotoImage(file="pic1.png")
background_label = tk.Label(root, image=background_image)
background_label.place(relwidth=1, relheight=1)

label_link = tk.Label(root, text="Enter Link:")
label_link.place(x=20, y=20)
entry_link = tk.Entry(root, width=40)
entry_link.place(x=100, y=20)

label_email = tk.Label(root, text="Enter Email:")
label_email.place(x=20, y=60)
entry_email = tk.Entry(root, width=40)
entry_email.place(x=100, y=60)

output_entry = scrolledtext.ScrolledText(root, width=70, height=10, wrap=tk.WORD)
output_entry.place(x=20, y=100)

button_scan = tk.Button(root, text="Scan Link", command=main_process)
button_scan.place(x=20, y=300)

root.mainloop() 
