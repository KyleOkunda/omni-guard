from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import DependencyFile, ScanReport, Vulnerability
from .utils import parse_dependency_files, check_vulnerabilities

@login_required
def upload_dependency_view(request):
    if request.method == 'POST':
        if 'dependency_file' not in request.FILES:
            return render(request, 'dependency_analysis/upload.html', {'error': 'No file selected'})

        
        files = request.FILES.getlist('dependency_file') 
        firstFile = files[0]
        if firstFile.name.endswith("package.json"):
            ecosystem = "npm"
        elif firstFile.name == ("Pipfile"):
            ecosystem = "PyPI"
        elif firstFile.name.endswith("requirements.txt"):
            ecosystem = "PyPI"

        for file in files:
            if not (file.name.endswith('.json') or file.name.endswith('.txt') or file.name == ('Pipfile')):
                return render(request, 'dependency_analysis/upload.html', {'error': 'Unsupported file type. We only support package.json, requirements.txt, and Pipfile.'})
            
            if ecosystem == "npm" and not file.name.endswith('.json'):
                return render(request, 'dependency_analysis/upload.html', {'error': 'Mixed file types. Please upload files from the same ecosystem.'})
            
            if ecosystem == "PyPI" and not (file.name.endswith('.txt') or file.name == ('Pipfile')):
                return render(request, 'dependency_analysis/upload.html', {'error': 'Mixed file types. Please upload files from the same ecosystem.'})

        
        # 1. Parse Files
        dependencies = parse_dependency_files(files)
        
        # 2. Check Vulnerabilities
        vulns = check_vulnerabilities(dependencies, ecosystem, request)
        
        # 3. Save Report
        report = ScanReport.objects.create(
            user=request.user,            
            total_dependencies=len(dependencies),
            vulnerabilities_found=len(vulns)
        )
        
        # 4. Save Dependency Files
        for file in files:
            DependencyFile.objects.create(
                report=report,
                file_name=file.name
            )
        
        # 5. Save Vulnerabilities
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
