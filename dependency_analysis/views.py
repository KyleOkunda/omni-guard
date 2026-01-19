from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import ScanReport, Vulnerability
from .utils import parse_dependency_file, check_vulnerabilities

@login_required
def upload_dependency_view(request):
    if request.method == 'POST':
        if 'dependency_file' not in request.FILES:
            return render(request, 'dependency_analysis/upload.html', {'error': 'No file selected'})
            
        file = request.FILES['dependency_file']
        
        # 1. Parse File
        dependencies = parse_dependency_file(file)
        
        # 2. Check Vulnerabilities
        vulns = check_vulnerabilities(dependencies)
        
        # 3. Save Report
        report = ScanReport.objects.create(
            user=request.user,
            uploaded_file=file,
            total_dependencies=len(dependencies),
            vulnerabilities_found=len(vulns)
        )
        
        # 4. Save Vulnerabilities
        for v in vulns:
            Vulnerability.objects.create(
                report=report,
                library_name=v['library_name'],
                version=v['version'],
                cve_id=v['cve_id'],
                description=v['description'],
                severity=v['severity'],
                remediation=v['remediation']
            )
            
        return redirect('dependency_report_detail', report_id=report.id)
        
    return render(request, 'dependency_analysis/upload.html')

@login_required
def report_list_view(request):
    reports = ScanReport.objects.filter(user=request.user).order_by('-scan_date')
    return render(request, 'dependency_analysis/report_list.html', {'reports': reports})

@login_required
def report_detail_view(request, report_id):
    report = get_object_or_404(ScanReport, id=report_id, user=request.user)
    vulnerabilities = report.vulnerabilities.all()
    return render(request, 'dependency_analysis/report_detail.html', {
        'report': report,
        'vulnerabilities': vulnerabilities
    })
