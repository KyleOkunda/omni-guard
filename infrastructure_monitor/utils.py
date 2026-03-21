import errno
import socket

# Mock "Shodan" Data
MOCK_PORTS = {
    '8.8.8.8': [{'port': 53, 'service': 'DNS', 'risk': False}, {'port': 443, 'service': 'HTTPS', 'risk': False}],
    'bad-site.com': [
        {'port': 80, 'service': 'HTTP', 'risk': False}, 
        {'port': 21, 'service': 'FTP', 'risk': True}, 
        {'port': 23, 'service': 'Telnet', 'risk': True}
    ],
    'example.com': [{'port': 80, 'service': 'HTTP', 'risk': False}, {'port': 443, 'service': 'HTTPS', 'risk': False}],
}

def scan_target(target):
    """
    Scanning a target.
    Returns:
    {
        'ports': [{'port': 80, "scanStatus": "Success"  'service': 'HTTP', 'risk': False}, ...]
        
    }
    """
    print(f"Scanning target: {target}")
    highRiskPorts = [{"port": 20, 'service': 'FTP (File Transfer Protocol)', 'associatedRisk': "Transmits credentials and data in cleartext. Vulnerable to packet sniffing, brute-force attacks, and anonymous login exploits. Use SFTP (Port 22) instead."},
                     {"port": 21, 'service': 'FTP (File Transfer Protocol)', 'associatedRisk': "Transmits credentials and data in cleartext. Vulnerable to packet sniffing, brute-force attacks, and anonymous login exploits. Use SFTP (Port 22) instead."},
                     {"port": 23, 'service': 'Telnet', 'associatedRisk': "Completely unencrypted communication. Attackers can easily intercept passwords and commands. Always use SSH instead."},
                     {"port": 25, 'service': 'SMTP (Simple Mail Transfer Protocol)', 'associatedRisk': "If not configured as an authorized mail server, it can be hijacked for email spoofing and open relay spam attacks."},
                     {"port": 53, 'service': 'DNS (Domain Name System)', 'associatedRisk': "If left open as a public recursive resolver, attackers can use it for massive DDoS amplification attacks."},
                     {"port": 69, 'service': 'TFTP (Trivial File Transfer Protocol)', 'associatedRisk': "Lacks any authentication mechanism. Attackers can upload malicious payloads or download sensitive configuration files."},
                     {"port": 110, 'service': 'POP3/IMAP', 'associatedRisk': "Legacy email retrieval protocols that transmit credentials in cleartext. Vulnerable to interception. Use POP3S (995) and IMAPS (993) instead."},
                     {"port": 143, 'service': 'POP3/IMAP', 'associatedRisk': "Legacy email retrieval protocols that transmit credentials in cleartext. Vulnerable to interception. Use POP3S (995) and IMAPS (993) instead."},
                     {"port": 135, 'service': 'RPC/NetBIOS', 'associatedRisk': "Windows file and printer sharing. Highly vulnerable to information disclosure and lateral movement. Often targeted for network reconnaissance."},
                     {"port": 137, 'service': 'RPC/NetBIOS', 'associatedRisk': "Windows file and printer sharing. Highly vulnerable to information disclosure and lateral movement. Often targeted for network reconnaissance."},
                     {"port": 138, 'service': 'RPC/NetBIOS', 'associatedRisk': "Windows file and printer sharing. Highly vulnerable to information disclosure and lateral movement. Often targeted for network reconnaissance."},
                     {"port": 139, 'service': 'RPC/NetBIOS', 'associatedRisk': "Windows file and printer sharing. Highly vulnerable to information disclosure and lateral movement. Often targeted for network reconnaissance."},
                     {"port": 445, 'service': 'SMB (Server Message Block)', 'associatedRisk': "One of the most dangerous ports to leave exposed. Historically exploited by ransomware like WannaCry and NotPetya via vulnerabilities like EternalBlue."},
                     {"port": 161, 'service': 'SNMP (Simple Network Management Protocol)', 'associatedRisk': "SNMPv1 and v2c use cleartext community strings. Easily exploited for network mapping, information disclosure, and DDoS amplification."},
                     {"port": 162, 'service': 'SNMP (Simple Network Management Protocol)', 'associatedRisk': "SNMPv1 and v2c use cleartext community strings. Easily exploited for network mapping, information disclosure, and DDoS amplification."},                     
                     {"port": 389, 'service': 'LDAP (Lightweight Directory Access Protocol)', 'associatedRisk': "Used for Active Directory lookups. Exposing it risks severe information disclosure (user lists, structures) and UDP amplification attacks."},
                     {"port": 1433, 'service': 'MS SQL', 'associatedRisk': "Prime targets for brute-force attacks and SQL injection. Should only be accessible from authorized application servers, never the public internet."},
                     {"port": 1434, 'service': 'MS SQL', 'associatedRisk': "Prime targets for brute-force attacks and SQL injection. Should only be accessible from authorized application servers, never the public internet."},                     
                     {"port": 3306, 'service': 'MySQL/MariaDB', 'associatedRisk': "Prime targets for brute-force attacks and SQL injection. Should only be accessible from authorized application servers, never the public internet."},
                     {"port": 3389, 'service': 'RDP (Remote Desktop Protocol)', 'associatedRisk': "A primary entry point for ransomware gangs. Highly susceptible to brute-force attacks, credential stuffing, and unpatched vulnerabilities (e.g., BlueKeep)"},
                     {"port": 5900, 'service': 'VNC (Virtual Network Computing)', 'associatedRisk': "Remote access protocol that is frequently misconfigured with weak or no passwords, leading to direct system takeover."}
                     ]

    ports = [] #List of dicts
    for port in highRiskPorts:            
        scan_dict = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket using IPv4        
        sock.settimeout(2)   
        result = sock.connect_ex((target, port['port'])) 
        sock.close()

        scan_dict["port"] = port['port']
        scan_dict["service"] = port['service'] 
        
        if result == 0:
            scan_dict["scanStatus"] = "Success"
            scan_dict["risk"] = True
            scan_dict["exploit_vector"] = port['associatedRisk']
        elif result == errno.ECONNREFUSED:
            scan_dict["scanStatus"] = "Connection Refused"
            scan_dict["risk"] = False
            scan_dict["exploit_vector"] = "Port is closed, no direct risk."
        elif result == errno.EHOSTUNREACH:
            scan_dict["scanStatus"] = "Host Unreachable. Path to Destination Unavailable"
            scan_dict["risk"] = "Unevaluated"
            scan_dict["exploit_vector"] = "Port Unevaluated"
        elif result == errno.ETIMEDOUT or result == errno.EAGAIN or result == errno.EWOULDBLOCK:
            scan_dict["scanStatus"] = "Connection Attempt Timed Out. (Firewall Might Be Blocking Access to Target)"
            scan_dict["risk"] = False
            scan_dict["exploit_vector"] = "Port might be open but failed to communicate or Firewall might be present to prevent access. Either way, port was not reached which is a good thing."
        elif result == errno.ENETUNREACH:
            scan_dict["scanStatus"] = "Network Unreachable. (Might Be No Internet Access)"
            scan_dict["risk"] = "Unevaluated"
            scan_dict["exploit_vector"] = "Port Unevaluated"
        elif result ==  errno.EACCES or result == errno.EPERM:
            scan_dict["scanStatus"] = "Permission Denied. (Might Be Your Local Firewall/Antivirus Blocking)"
            scan_dict["risk"] = "Unevaluated"
            scan_dict["exploit_vector"] = "Port Unevaluated"
        else:
            scan_dict["scanStatus"] = f"Unknown Error (Error Code: {result})"
            scan_dict["risk"] = "Unevaluated"
            scan_dict["exploit_vector"] = "Port Unevaluated"

        print("The result of the scan: " , result)
        print("--------------- Scan Details -----------------")
        print(f"Scanned port: {scan_dict['port']} for service: {scan_dict["service"]}")
        print("Scan Status: " , scan_dict["scanStatus"])
        print("Risk Assessment: " , "High Risk" if scan_dict["risk"] == True else "No Direct Risk" if scan_dict["risk"] == False else "Unevaluated")
        print("Exploit Vector: " , scan_dict["exploit_vector"])
        print()
        
        ports.append(scan_dict)
    
    return ports
    

    



def calculate_grade(scan_data):
    """
    Score = 100 - (Risk Ports * 20) - (Expired SSL * 30)
    """
    base_score = 100
    numberOfRiskports = 0
    for port in scan_data:
        if port['risk'] == True:
            numberOfRiskports += 1
    
    risk_ports = numberOfRiskports    
    print(f"Number of high-risk ports: {risk_ports}")    
    ssl_expired = False 
    #ssl_expired = scan_data['ssl_expired']
    
    penalty_ports = risk_ports * 20
    penalty_ssl = 30 if ssl_expired else 0


    
    score = base_score - penalty_ports - penalty_ssl
    if score < 0: score = 0
    
    # Grade assignment
    if score >= 90: grade = 'A'
    elif score >= 80: grade = 'B'
    elif score >= 70: grade = 'C'
    elif score >= 60: grade = 'D'
    else: grade = 'F'
    
    return score, grade
