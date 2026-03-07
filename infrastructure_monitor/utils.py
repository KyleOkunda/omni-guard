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
    ports = [] #List of dicts
    scan_dict = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket using IPv4
    sock.settimeout(2)    
    result = sock.connect_ex((target, 80))    
    sock.close()

    scan_dict["port"] = 80
    scan_dict["service"] = "HTTP"    
    
    if result == 0:
        scan_dict["scanStatus"] = "Success"
        scan_dict["risk"] = True
    elif result == errno.ECONNREFUSED:
        scan_dict["scanStatus"] = "Connection Refused"
        scan_dict["risk"] = False
    elif result == errno.EHOSTUNREACH:
        scan_dict["scanStatus"] = "Host Unreachable. Path to Destination Unavailable"
        scan_dict["risk"] = "Unevaluated"
    elif result == errno.ETIMEDOUT:
        scan_dict["scanStatus"] = "Connection Timed Out. (Firewall Might Be Blocking Access to Target)"
        scan_dict["risk"] = False
    elif result == errno.ENETUNREACH:
        scan_dict["scanStatus"] = "Network Unreachable. (Might Be No Internet Access)"
        scan_dict["risk"] = "Unevaluated"
    elif result ==  errno.EACCES or result == errno.EPERM:
        scan_dict["scanStatus"] = "Permission Denied. (Might Be Your Local Firewall/Antivirus Blocking)"
        scan_dict["risk"] = "Unevaluated"
    else:
        scan_dict["scanStatus"] = f"Unknown Error (Error Code: {result})"
        scan_dict["risk"] = "Unevaluated"

    print("The result of the scan: " , result)
    print("Sacn Status: " , scan_dict["scanStatus"])
    
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
