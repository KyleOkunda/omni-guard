import json
import re

# Mock Database of Vulnerabilities
MOCK_VULNDB = {
    'requests': [
        {'range': '<2.20.0', 'cve': 'CVE-2018-18074', 'severity': 'High', 'desc': 'Redirect handling vulnerability'},
        {'range': '<2.0.0', 'cve': 'CVE-2015-2296', 'severity': 'Medium', 'desc': 'Session fixation'}
    ],
    'django': [
        {'range': '<3.2.10', 'cve': 'CVE-2021-45115', 'severity': 'High', 'desc': 'Denial-of-service possibility in UserAttributeSimilarityValidator'},
        {'range': '<4.0.1', 'cve': 'CVE-2022-22818', 'severity': 'Medium', 'desc': 'XSS in debug page'}
    ],
    'lodash': [
        {'range': '<4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'Critical', 'desc': 'Command Injection via template'}
    ]
}

def parse_dependency_file(file):
    """
    Parses an uploaded file (JSON or TXT) and returns a list of dicts:
    [{'name': 'lib_name', 'version': '1.2.3'}]
    """
    dependencies = []
    filename = file.name.lower()
    
    try:
        content = file.read().decode('utf-8')
        
        if filename.endswith('.json'):
            data = json.loads(content)
            # Support package.json structure
            deps = data.get('dependencies', {})
            deps.update(data.get('devDependencies', {}))
            
            # If it's just a simple list or dict
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    # Clean version string (remove ^, ~)
                    clean_ver = re.sub(r'[^\d.]', '', ver)
                    dependencies.append({'name': name, 'version': clean_ver})
                    
        elif filename.endswith('.txt'):
            # requirements.txt format: name==version
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '==' in line:
                    parts = line.split('==')
                    dependencies.append({'name': parts[0], 'version': parts[1]})
                    
    except Exception as e:
        print(f"Error parsing file: {e}")
        return []

    return dependencies

def compare_versions(current_ver, vulnerability_range):
    """
    Simple SemVer check.
    Supports <, <=, >, >=, ==
    Returns True if current_ver satisfies vulnerability_range
    """
    try:
        # Very basic implementation
        op_match = re.match(r'(<|<=|>|>=|==)(.*)', vulnerability_range)
        if not op_match:
            return False
            
        op, target_ver = op_match.groups()
        
        c_parts = [int(x) for x in current_ver.split('.') if x.isdigit()]
        t_parts = [int(x) for x in target_ver.split('.') if x.isdigit()]
        
        # Pad with zeros
        while len(c_parts) < 3: c_parts.append(0)
        while len(t_parts) < 3: t_parts.append(0)
        
        if op == '<': return c_parts < t_parts
        if op == '<=': return c_parts <= t_parts
        if op == '>': return c_parts > t_parts
        if op == '>=': return c_parts >= t_parts
        if op == '==': return c_parts == t_parts
        
    except:
        return False
        
    return False

def check_vulnerabilities(dependencies):
    """
    Checks list of dependencies against MOCK_VULNDB.
    Returns list of vulnerabilities found.
    """
    found_vulns = []
    
    for dep in dependencies:
        name = dep['name'].lower()
        version = dep['version']
        
        if name in MOCK_VULNDB:
            for vuln in MOCK_VULNDB[name]:
                if compare_versions(version, vuln['range']):
                    found_vulns.append({
                        'library_name': dep['name'],
                        'version': version,
                        'cve_id': vuln['cve'],
                        'description': vuln['desc'],
                        'severity': vuln['severity'],
                        'remediation': f"Upgrade to a version not matching {vuln['range']}"
                    })
                    
    return found_vulns
