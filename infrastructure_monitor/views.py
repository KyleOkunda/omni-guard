from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import NetworkScan, ExposedPort
from .utils import scan_target, calculate_grade

@login_required
def scan_network_view(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        if not target:
            return render(request, 'infrastructure_monitor/scan.html', {'error': 'Please enter a target'})
            
        # 1. Scan
        data = scan_target(target)
        
        # 2. Score
        score, grade = calculate_grade(data)
        
        # 3. Save
        scan = NetworkScan.objects.create(
            user=request.user,
            target=target,
            score=score,
            grade=grade
        )
        
        for p in data['ports']:
            ExposedPort.objects.create(
                scan=scan,
                port_number=p['port'],
                service_name=p['service'],
                is_risk=p['risk']
            )
            
        return redirect('network_report_detail', report_id=scan.id)

    return render(request, 'infrastructure_monitor/scan.html')

@login_required
def report_list_view(request):
    scans = NetworkScan.objects.filter(user=request.user).order_by('-scan_date')
    return render(request, 'infrastructure_monitor/report_list.html', {'scans': scans})

@login_required
def report_detail_view(request, report_id):
    scan = get_object_or_404(NetworkScan, id=report_id, user=request.user)
    ports = scan.exposed_ports.all()
    
    # Calculate simple stats for view
    risk_ports = ports.filter(is_risk=True).count()
    
    return render(request, 'infrastructure_monitor/report_detail.html', {
        'scan': scan,
        'ports': ports,
        'risk_ports': risk_ports
    })
