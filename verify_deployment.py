import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'security_platform.settings')
django.setup()

from django.contrib.auth.models import User
from django.test import Client
from dependency_analysis.models import ScanReport
from infrastructure_monitor.models import NetworkScan
from endpoint_monitor.models import Agent

def run_verification():
    print("--- Starting Verification ---")
    
    # 1. User Creation
    user, created = User.objects.get_or_create(username='testadmin', email='admin@test.com')
    if created:
        user.set_password('admin123')
        user.save()
        print("✅ User created")
    else:
        print("ℹ️ User already exists")

    client = Client()
    login_success = client.login(username='testadmin', password='admin123')
    if login_success:
        print("✅ Login successful")
    else:
        print("❌ Login failed")
        return

    # 2. Module A: Dependency Analysis (Unit Test Utils)
    from dependency_analysis.utils import check_vulnerabilities, compare_versions
    deps = [{'name': 'requests', 'version': '1.0.0'}]
    vulns = check_vulnerabilities(deps)
    if len(vulns) > 0:
        print(f"✅ Module A Logic: Found {len(vulns)} vulnerabilities in v1.0.0 (Expected)")
    else:
        print("❌ Module A Logic: Failed to find vulnerabilities")

    # 3. Module B: Infrastructure Monitor (Unit Test Utils)
    from infrastructure_monitor.utils import scan_target, calculate_grade
    scan_data = scan_target('bad-site.com')
    score, grade = calculate_grade(scan_data)
    if grade in ['D', 'F']: # Expect bad grade for bad-site.com
        print(f"✅ Module B Logic: 'bad-site.com' got grade {grade} (Expected Low)")
    else:
        print(f"❌ Module B Logic: 'bad-site.com' got unexpectedly high grade {grade}")

    # 4. Module C: Endpoint Monitor (Integration Test API)
    payload = {
        'agent_id': 'test-agent-01',
        'hostname': 'TEST-PC',
        'active_hooks_list': ['User32.dll', 'malicious.dll'] # malicious should trigger risk
    }
    response = client.post(
        '/api/heartbeat/',
        data=json.dumps(payload),
        content_type='application/json'
    )
    
    if response.status_code == 200:
        resp_data = response.json()
        if resp_data.get('risk_detected'):
             print("✅ Module C API: Risk detected successfully")
        else:
             print("❌ Module C API: Risk NOT detected (Expected Risk)")
             
        # Check DB
        agent = Agent.objects.get(agent_id='test-agent-01')
        if agent.status == 'Risk':
            print("✅ Module C DB: Agent status updated to Risk")
        else:
            print(f"❌ Module C DB: Agent status is {agent.status}")
    else:
        print(f"❌ Module C API: Failed with status {response.status_code}")
        print(response.content)

    print("--- Verification Complete ---")

if __name__ == '__main__':
    run_verification()
