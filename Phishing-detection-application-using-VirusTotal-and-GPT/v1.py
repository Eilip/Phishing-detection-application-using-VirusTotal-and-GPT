import os
import json
import requests

# Check if <link>sus.js</link> and <link>blacklist.js</link> exist. If not, create these JSON files.
if not os.path.exists("sus.js"):
    with open("sus.js", "w") as file:
        json.dump({}, file)

if not os.path.exists("blacklist.js"):
    with open("blacklist.js", "w") as file:
        json.dump({}, file)

#  Prompt the user to enter a link.
link = input("Enter the link: ")

# + Convert the input into a string variable named "link".
link = str(link)

# Step 4: Use the VirusTotal URL checkup API on the "link" variable.
virus_total_api_key = "YOUR_VIRUS_TOTAL_API_KEY"
url = f"https://www.virustotal.com/api/v3/urls/{link}"
headers = {"x-apikey": virus_total_api_key}
response = requests.get(url, headers=headers)
result = response.json()

# Step 5: Check if the result indicates phishing
if "data" in result and "attributes" in result["data"] and "status" in result["data"]["attributes"]:
    if result["data"]["attributes"]["status"] == "phishing":
        sender_email = input("Enter the email of the sender: ")

        # Store the link, current time, email, and DNS lookup of the domain in <link>blacklist.js</link>
        with open("<link>blacklist.js</link>", "r") as file:
            blacklist_data = json.load(file)
        
        blacklist_data[link] = {
            "time": "CURRENT_TIME",
            "email": sender_email,
            "dnslookup": "DNS_LOOKUP_RESULT"
        }

        with open("<link>blacklist.js</link>", "w") as file:
            json.dump(blacklist_data, file)

        # End the program
        exit()

# Step 6: Use the GPT API to analyze the link
gpt_prompt = f"Analyze the link '{link}' by splitting data into its protocol, domain name, subdomain, and scanning each part for security or any possibility of phishing. Check for the following criteria:\n\n- Old and insecure protocol\n- Domain name similarity to famous sites, but with added symbols\n- Suspiciously long URL\n- URL containing '@' symbol\n- Redirection using '//' to another website\n- Subdomain or multi-subdomain\n- Multiple '.' after 'www'\n\nIf all of these criteria are analyzed and the result comes out as suspicious, return the answer as 'suspicious'; otherwise, return 'no'."

# Step 7: If the result of GPT comes out as a suspicious link, ask for the email and add the link, current time, DNS lookup, and email to <link>sus.js</link>
gpt_result = "GPT_RESULT"
if gpt_result == "suspicious":
    sender_email = input("Enter the email of the sender: ")

    with open("<link>sus.js</link>", "r") as file:
        sus_data = json.load(file)
    
    sus_data[link] = {
        "time": "CURRENT_TIME",
        "email": sender_email,
        "dnslookup": "DNS_LOOKUP_RESULT"
    }

    with open("<link>sus.js</link>", "w") as file:
        json.dump(sus_data, file)
else:
    # Step 8: If the result of GPT comes out as a safe link, give the output "Safe to click" and close the program.
    print("Safe to click")
    exit()