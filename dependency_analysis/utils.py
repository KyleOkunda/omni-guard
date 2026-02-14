import json
import os
import re
import time
import requests
from django.shortcuts import render

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

def parse_dependency_files(files):    
    """
    Parses uploaded files (JSON or TXT) and returns a list of dicts:
    [{'name': 'lib_name', 'version': '1.2.3'}]
    """
    dependencies = []
    #filename = file.name.lower()
    
    try:
       for file in files:
            filename = file.name.lower()
            content = file.read().decode('utf-8')            
        
            if filename.endswith('.json'):
                print(f"Parsing JSON file: {filename}")
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
                print(f"Parsing TXT file: {filename}")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '==' in line:
                        parts = line.split('==')
                        dependencies.append({'name': parts[0], 'version': parts[1]})

            elif filename == 'pipfile':
                print(f"Parsing Pipfile: {filename}")                
                packages = content.split('[packages]')[1].split('[dev-packages]')[0].strip().splitlines()
                for pkg in packages:
                    print(pkg)
                    if not pkg.strip() or pkg.strip().startswith('#'):
                        continue
                    if ' = ' in pkg:
                        name, ver = pkg.split(' = ', 1)
                        dependencies.append({'name': name.strip(), 'version': ver.strip()})


    except Exception as e:
        print(f"Error parsing file(s): {e}")
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

def check_vulnerabilities(dependencies, ecosystem, request):
    """
    Checks list of dependencies against MOCK_VULNDB.
    Returns list of vulnerabilities found.
    """
    found_vulns = []
    osvUrl = os.getenv("OSV_URL")
    for dep in dependencies:
        depName = dep['name']
        depVersion = dep['version']
        payload = { "package":
          { "name": depName,
            "ecosystem": ecosystem
             },
            "version": depVersion }

        print(f"Checking {depName} version {depVersion} against OSV")  

        try:
            response = requests.post(osvUrl, json=payload)
            if response.status_code == 200:
                data = response.json()                              
                print(f"Found {len(data.get('vulns', []))} vulnerabilities:\n")
                for item in data.get('vulns', []):                                        
                    severity = item.get("severity", "N/A")
                    if(severity!= "N/A"):
                        found_vulns.append({
                            'library_name': depName,
                            'version': depVersion,
                            'cve_id': item.get('id', 'N/A'),
                            'description': item.get('details', 'No description provided'),
                            'severity': item.get("severity", "N/A")[0].get("score", "N/A"),
                            'remediation': "Please Update Dependency to Latest Version"
                        })
                    else:
                        found_vulns.append({
                            'library_name': depName,
                            'version': depVersion,
                            'cve_id': item.get('id', 'N/A'),
                            'description': item.get('details', 'No description provided'),
                            'severity': severity,
                            'remediation': "Please Update Dependency to Latest Version"
                        })
            else:
                print(f"OSV API error for {depName} version {depVersion}: {response.status_code} \n {response.text}")
                return

        except Exception as e:
                print(f"Error querying OSV for {depName} version {depVersion}: \n {repr(e)} ")
                return render(request, 'dependency_analysis/upload.html', {'error': 'Error checking vulnerabilities. Please try again later.'})
                    
    return found_vulns
