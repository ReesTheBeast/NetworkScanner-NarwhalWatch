# Narwhal Watch - Vulnerability Scanner

**Narwhal Watch** is a Python-based network and web application vulnerability scanner designed to assess security weaknesses in networks and web applications. This tool is suitable for both educational purposes and authorized security testing.

## Features

- **Network Scanning**: Scans a specified target IP for open ports commonly used by network services.
- **Operating System Detection**: Attempts to identify the OS type based on response signatures.
- **Web Application Vulnerability Checks**:
  - Detects missing security headers.
  - Scans for SQL Injection vulnerabilities.
  - Checks for Cross-Site Scripting (XSS) risks.
  - Tests for directory traversal vulnerabilities.
- **Brute-force Login Test**: Attempts common username and password combinations.
- **Data Leak Checks**:
  - Uses the [Have I Been Pwned (HIBP) API](https://haveibeenpwned.com/API/v3) to check if a domain has been part of any data breaches.
  - Searches GitHub for files containing the specified domain for potential data exposure.

## Prerequisites

- Python 3.6 or higher
- Required Libraries:
  - `requests`
  - `colorama`
  - `socket`
- **Optional API Access**:
  - HIBP API Key
  - GitHub API Token (recommended for GitHub domain leak checks)

## Installation

1. Clone the repository:

   git clone https://github.com/ReesTheBeast/narwhal-watch.git
   cd narwhal-watch
Install the necessary libraries:

pip install -r requirements.txt
Set up your API keys if you want to access all features.

Usage
To run the vulnerability scanner, use:


python main.py
You’ll be prompted to enter a target IP address for network scanning.
Then, enter a target URL for web application vulnerability scanning.
If you have API keys, enter them to enable the domain leak checks on HIBP and GitHub.
Output and Reporting
The scanner outputs a detailed report to the terminal, including:

Network Scan Results: Displays open ports detected on the target IP.
Operating System Information: Attempts to identify the detected OS.
Web Application Scan Results: Lists potential vulnerabilities, including:
Missing security headers.
SQL Injection.
Cross-Site Scripting (XSS).
Directory traversal vulnerabilities.
Brute-force login test results.
Domain Leak and GitHub Leak Check: Shows any data leaks associated with the domain.
Example Output
--- Vulnerability Assessment Report ---
Scan Date: YYYY-MM-DD HH:MM:SS

Network Scan Results:
  Target IP: 192.168.1.1
  Open Ports:
    - Port 80
    - Port 443

Operating System Information:
  Detected OS: Linux

Web Application Scan Results:
  Missing Headers: Missing Headers -> X-Frame-Options, Content-Security-Policy
  Sql Injection: Vulnerable
  Xss: Not Vulnerable
  Directory Traversal: Vulnerable
  Brute-force Login: Not Vulnerable

--- Domain Leak Check Results ---
Domain Leaks (HIBP): No breaches found for this domain.

--- GitHub Leak Check Results ---
GitHub check skipped.
Disclaimer
This tool is intended strictly for ethical hacking and authorized testing. Unauthorized scanning or testing of systems without permission is illegal. Always ensure you have proper authorization before performing any security assessments.

License
This project is licensed under the MIT License.
