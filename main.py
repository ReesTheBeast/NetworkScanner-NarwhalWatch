import socket
import requests
from datetime import datetime
import random
from colorama import Fore, Style,init
import time
import os
from urllib.parse import urlparse
import platform

# Initialize colorama
init(autoreset=True)

def animated_logo():
    logo = [
        f"{Fore.LIGHTBLUE_EX}-------------------------------------------=:-@@@@@@@%-:------------------------------------",
        f"{Fore.BLUE}-----------------------------------------:+@@@@@@@@+:---------------------------------------",
        f"{Fore.BLUE}--------------------------------------:=@@@@@@@@#-:-----------------------------------------",
        f"{Fore.LIGHTBLUE_EX}----------------------+@@@@@@@%###*=-+@@@@@@@@#:-=------------------------------------------",
        f"{Fore.LIGHTCYAN_EX}-----------------=%@@@%%%#%##%%###*#@@@#@@%%+-----------------------------------------------",
        f"{Fore.CYAN}---------------=@@%#####%%#%%%#####@%@@@%#-:------------------------------------------------",
        f"{Fore.CYAN}-------------=@%%##%%%%%%%#########*%@%%+=#+---------------------==-------------------+#+---",
        f"{Fore.LIGHTCYAN_EX}-----------=##%@*####################*+*####=--------------------**------------------*%*----",
        f"{Fore.LIGHTBLUE_EX}----------=#%%=+:*###########################-------------------+##*--------------=###=----",
        f"{Fore.BLUE}----------#@@@%#%############################:------------------+##%*:------------*%%##-----",
        f"{Fore.BLUE}---------*#@@@@@%############################:------------------+###@%----------*%%%##*-----",
        f"{Fore.LIGHTBLUE_EX}---------###%@@%#############################:------------------=####%@#=------#%%####*-----",
        f"{Fore.LIGHTCYAN_EX}--------*####################################--------------------*######@@+:-:%%%#####*-----",
        f"{Fore.CYAN}--------########################%@%=*#######+--------------------+########%#-#%%%#####*-----",
        f"{Fore.CYAN}-------+#########################=-:=#######=---------------------*###########%%######=-----",
        f"{Fore.LIGHTCYAN_EX}-------#######################%@@@##%######=-----------------------+#################+------",
        f"{Fore.LIGHTBLUE_EX}------########################%@@@@@@#####*-------------------------:*##############--------",
        f"{Fore.BLUE}-----=#########################%@@@%######+----------------------------+#########*----------",
        f"{Fore.BLUE}-----####@@@@@@@%#########################+-------------------------------#####*:-----------",
        f"{Fore.LIGHTBLUE_EX}----=#@@@@@@@@@@@@@#######################+-------------------------------=####=------------",
        f"{Fore.LIGHTCYAN_EX}----#@@@@@@@@@@@@@@@@%####################*-------------------------------:####-------------",
        f"{Fore.GREEN}===========================================================================================",                                                                
        f"{Fore.CYAN}       __  __     __                      __      _____                                     ",
        f"{Fore.LIGHTCYAN_EX}      / | / /__  / /__      ______  _____/ /__   / ___/_________ _____  ____  ___  _____    ",
        f"{Fore.LIGHTBLUE_EX}     /  |/ / _ \/ __/ | /| / / __ \/ ___/ //_/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/    ",
        f"{Fore.BLUE}    / /|  /  __/ /_ | |/ |/ / /_/ / /  / , <    ___/ / /__/ /_/ / / / / / / /  __/ /         ",
        f"{Fore.BLUE}   /_/ |_/\___/\__/ |__/|__/\____/_/  /_/|_|   /____/\___/\__ _/_/ /_/_/ /_/\___/_/          ",
    ]

    for line in logo:
        print(line)
        time.sleep(0.1)  
    print(f"{Fore.GREEN}\n" + "=" * 39 + " ɴᴀʀᴡʜᴀʟ ᴡᴀᴛᴄʜ " + "=" * 39 + "\n")

def get_random_user_agent():
    return random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3", 
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36", 
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/47.0", 
    ])


# Port Scanner
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

def network_scan(target_ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]
    open_ports = []
    print(f"\nStarting network scan on {target_ip}...")
    for port in common_ports:
        if scan_port(target_ip, port):
            print(f"  - Port {port} is open.")
            open_ports.append(port)
    return open_ports

#Check for database leak
def check_domain_leak(api_key, domain):
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "DatabaseLeakChecker"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()  
        elif response.status_code == 404:
            return "No breaches found for this domain."
        else:
            return f"Error: {response.status_code}"
    except requests.RequestException as e:
        return f"Request failed: {e}"

def github_search(token, domain):
    url = f"https://api.github.com/search/code?q={domain}+in:file"
    headers = {"Authorization": f"token {token}"}
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else "No results or error."
    except requests.RequestException as e:
        return f"Request failed: {e}"

# OS Detection
def detect_os(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, 80))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip))
        response = sock.recv(1024).decode()
        sock.close()
        if "Server" in response:
            return response.split("Server: ")[1].split("\r\n")[0]
    except Exception as e:
        print(f"Error detecting OS: {e}")
    return "Unknown OS"

# Web Application Vulnerability Checks
def check_security_headers(url):
    headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    missing_headers = []
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": get_random_user_agent()})
        for header in headers:
            if header not in response.headers:
                missing_headers.append(header)
    except requests.RequestException:
        print("Failed to reach the web server.")
    return missing_headers

def check_sql_injection(url):
    test_url = f"{url}/?id=1' OR '1'='1"
    try:
        response = requests.get(test_url, timeout=5, headers={"User-Agent": get_random_user_agent()})
        if "SQL" in response.text or "error" in response.text:
            return True
    except requests.RequestException:
        pass
    return False

def check_xss(url):
    test_url = f"{url}/?q=<script>alert(1)</script>"
    try:
        response = requests.get(test_url, timeout=5, headers={"User-Agent": get_random_user_agent()})
        if "<script>alert(1)</script>" in response.text:
            return True
    except requests.RequestException:
        pass
    return False

def check_directory_traversal(url):
    traversal_attempts = ["../", "..%2F", "..%252F"]
    for attempt in traversal_attempts:
        try:
            response = requests.get(f"{url}/{attempt}etc/passwd", timeout=5, headers={"User-Agent": get_random_user_agent()})
            if "root:" in response.text:
                return True
        except requests.RequestException:
            pass
    return False

# Brute-force Login Test (for demonstration)
def brute_force_login(url):
    login_url = f"{url}/login"
    common_usernames = ["admin", "user", "test"]
    common_passwords = ["password", "123456", "admin"]
    
    for username in common_usernames:
        for password in common_passwords:
            data = {"username": username, "password": password}
            try:
                response = requests.post(login_url, data=data, timeout=5, headers={"User-Agent": get_random_user_agent()})
                if "Welcome" in response.text or "Dashboard" in response.text:
                    return {"username": username, "password": password}
            except requests.RequestException:
                continue
    return None

# Scanning Web Application
def scan_web_application(url):
    print(f"\nScanning web application: {url}")
    vulnerabilities = {}
    
    missing_headers = check_security_headers(url)
    vulnerabilities['missing_headers'] = missing_headers if missing_headers else "None"
    
    vulnerabilities['sql_injection'] = "Vulnerable" if check_sql_injection(url) else "Not Vulnerable"
    vulnerabilities['xss'] = "Vulnerable" if check_xss(url) else "Not Vulnerable"
    vulnerabilities['directory_traversal'] = "Vulnerable" if check_directory_traversal(url) else "Not Vulnerable"
    
    brute_force_result = brute_force_login(url)
    vulnerabilities['brute_force_login'] = brute_force_result if brute_force_result else "Not Vulnerable"
    
    return vulnerabilities

# Generate Detailed Report to Terminal
def print_report(network_results, service_results, os_info, web_vulnerabilities):
    print("\n--- Vulnerability Assessment Report ---")
    print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\nNetwork Scan Results:")
    print(f"  Target IP: {network_results['target_ip']}")
    print("  Open Ports:")
    for port in network_results['open_ports']:
        print(f"    - Port {port}")

    print("\nOperating System Information:")
    print(f"  Detected OS: {os_info}")
    
    print("\nWeb Application Scan Results:")
    for vuln, result in web_vulnerabilities.items():
        if isinstance(result, list):
            print(f"  {vuln.capitalize()}: Missing Headers -> {', '.join(result) if result else 'None'}")
        elif isinstance(result, dict):
            print(f"  Brute-force Login: Vulnerable -> {result}")
        else:
            print(f"  {vuln.capitalize()}: {result}")

# Main Function
def main():
    # Network Scan
    target_ip = input(f"{Fore.GREEN}{Style.BRIGHT}ᴇɴᴛᴇʀ ᴛᴀʀɢᴇᴛ ɪᴘ ꜰᴏʀ ɴᴇᴛᴡᴏʀᴋ ꜱᴄᴀɴ: ")
    open_ports = network_scan(target_ip)
    os_info = detect_os(target_ip)
    service_info = {port: "Unknown Service" for port in open_ports} 

    # Web Application Scan
    target_url = input(f"{Fore.GREEN}{Style.BRIGHT}ᴇɴᴛᴇʀ ᴛᴀʀɢᴇᴛ ᴜʀʟ ꜰᴏʀ ᴡᴇʙ ᴀᴘᴘʟɪᴄᴀᴛɪᴏɴ ꜱᴄᴀɴ: ")
    web_vulns = scan_web_application(target_url)

    # Extract domain from URL for further checks
    domain = urlparse(target_url).netloc

    # Database Leak Check
    hibp_api_key = input("Enter Have I Been Pwned API key (or press Enter to skip): ")
    if hibp_api_key:
        domain_leaks = check_domain_leak(hibp_api_key, domain)
    else:
        domain_leaks = "HIBP check skipped."

    # GitHub Search for Domain References
    github_token = input("Enter GitHub API token (or press Enter to skip): ")
    if github_token:
        github_leaks = github_search(github_token, domain)
    else:
        github_leaks = "GitHub check skipped."

    # Report Results
    print_report(
        network_results={"target_ip": target_ip, "open_ports": open_ports},
        service_results=service_info,
        os_info=os_info,
        web_vulnerabilities=web_vulns
    )

    # Display Leak Information
    print("\n--- Domain Leak Check Results ---")
    print(f"Domain Leaks (HIBP): {domain_leaks}")
    
    print("\n--- GitHub Leak Check Results ---")
    if isinstance(github_leaks, dict) and 'items' in github_leaks:
        for item in github_leaks['items']:
            print(f"  - {item['html_url']}")
    else:
        print(github_leaks)

if __name__ == "__main__":
    animated_logo()
    main()
