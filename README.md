
# SQL Injection Detector with WAF Detection

## Original
Forked from https://github.com/aungsanoo-usa/sqli_detect.git

## Overview
This script is a powerful tool for detecting **SQL Injection vulnerabilities** and identifying **Web Application Firewall (WAF) behavior** in web applications. Designed for both single URL and bulk URL testing from a `urls.txt` file, it provides detailed insights into the security posture of your application.

## Features
- **SQL Injection Detection**:
  - Comprehensive payloads for error-based, union-based, and logical SQL injection techniques.
  - Tracks significant changes in response length and detects error messages.
  
- **Web Application Firewall (WAF) Detection**:
  - Identifies WAF behavior by observing HTTP status codes (`403`, `406`, etc.) and content changes.

- **Flexible Scanning**:
  - Test a single URL or scan multiple URLs from a `urls.txt` file.

- **User-Friendly Output**:
  - Color-coded results for vulnerabilities, WAF detection, and safe responses.

## Requirements
- Python 3.6 or later
- Libraries: `requests`, `colorama`

Install the required libraries using:
```bash
pip install requests colorama
```

## Sample target
1. google dork:
   ```bash
   $ git clone https://github.com/BullsEye0/dorks-eye
   $ python dorks-eye.py
   query > site:id inurl:/product.php?id=
   display > 100

   $ cat dork_results.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sed 's/=.*/=/' | sort | uniq > bsqli.txt
   $ python3 sqli_detect.py
   URL > 2
   file > bsqli.txt
   ```
2. Input url and filter:
   ```
   # Step 1: Run katana with passive sources and save output to a unified file (output/output.txt)
   echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "output.txt"

   # Step 2: Run katana actively with depth 5 and append results to output/output.txt
   katana -u "$website_url" -d 5 -f qurl | uro | anew "output.txt"

   # Step 3: Filter output/output.txt for different vulnerabilities
   # XSS
   cat "output.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > "xss_output.txt"

   # Open Redirect
   cat "output.txt" | gf or | sed 's/=.*/=/' | sort -u > "open_redirect_output.txt"

   # LFI
   cat "output.txt" | gf lfi | sed 's/=.*/=/' | sort -u > "lfi_output.txt"

   # SQLi
   cat "output.txt" | gf sqli | sed 's/=.*/=/' | sort -u > "sqli_output.txt"
   ``

## Usage
1. Run the script:
   ```bash
   python sqli_detect.py
   ```
2. Choose your scan type:
   - Enter `1` for a single URL scan.
   - Enter `2` to scan multiple URLs from a file (e.g., `urls.txt`).

3. Review the results in the terminal.

## Input Format
### Single URL
When prompted, enter a URL with a parameter:
```
http://example.com/page.php?id=
```

### Bulk URLs
Create a `urls.txt` file with one URL per line:
```
http://example.com/page.php?id=
http://test.com/item.php?item_id=
http://vulnerable-site.com/index.php?product_id=
```

## Example Output
### Vulnerable Target
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[+] SQL Injection Found with payload: ' OR 1=1; --
[!] WAF Detected: Payload '' caused HTTP 403
[+] SQL Injection Found with payload: ' UNION SELECT NULL,NULL,NULL--

[!] Scan complete.
[!!!] The target might be VULNERABLE to SQL Injection.
```

### Secure Target
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[-] No vulnerability with payload: '
[-] No vulnerability with payload: ' OR 1=1; --
[!] WAF behavior detected: Response length changed with payload: ' UNION SELECT NULL,NULL,NULL--

[!] Scan complete.
[+] The target is NOT vulnerable to SQL Injection.
```

### Bulk URLs Summary
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[+] SQL Injection Found with payload: ' OR '1'='1
[!] WAF Detected: Payload '' caused HTTP 406
[*] Starting SQL Injection scan for: http://secure-site.com/index.php?item_id=
[-] No vulnerability with payload: '

[!] Scan complete.
Summary:
http://example.com/page.php?id= -> VULNERABLE
http://secure-site.com/index.php?item_id= -> NOT VULNERABLE
```

## Payloads Used
The script tests a wide variety of SQL injection payloads, including:
- `'`
- `''`
- `' OR 1=1; --`
- `' UNION SELECT NULL,NULL,NULL--`
- And many more...

For the full list, refer to the `scan()` function in the script.

## Contributions
Contributions are welcome! If you'd like to improve the tool, feel free to fork the repository, make your changes, and submit a pull request.

## Disclaimer
This tool is intended for **educational purposes** and **authorized penetration testing** only. Ensure you have permission to test any target. The developers are not responsible for any misuse of this tool.

