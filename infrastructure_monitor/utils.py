import random

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
    Simulates scanning a target.
    Returns:
    {
        'ports': [{'port': 80, 'service': 'HTTP', 'risk': False}, ...],
        'ssl_expired': False
    }
    """
    # Simulate randomness if target not in mock DB
    if target in MOCK_PORTS:
        ports = MOCK_PORTS[target]
        ssl_expired = False
        if target == 'bad-site.com': ssl_expired = True
    else:
        # Random generation for unknown targets
        ports = []
        common_ports = [
            (80, 'HTTP', False), (443, 'HTTPS', False), (22, 'SSH', False), 
            (21, 'FTP', True), (3306, 'MySQL', True), (23, 'Telnet', True)
        ]
        # Pick 1-4 random ports
        num_ports = random.randint(1, 4)
        for _ in range(num_ports):
            p = random.choice(common_ports)
            ports.append({'port': p[0], 'service': p[1], 'risk': p[2]})
        
        ssl_expired = random.choice([True, False]) if 'HTTPS' in [p['service'] for p in ports] else False

    return {
        'ports': ports,
        'ssl_expired': ssl_expired
    }

def calculate_grade(scan_data):
    """
    Score = 100 - (Risk Ports * 20) - (Expired SSL * 30)
    """
    base_score = 100
    
    risk_ports = sum(1 for p in scan_data['ports'] if p['risk'])
    ssl_expired = scan_data['ssl_expired']
    
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
