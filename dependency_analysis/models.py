from django.db import models
from django.contrib.auth.models import User

class ScanReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_file = models.FileField(upload_to='dependency_uploads/')
    scan_date = models.DateTimeField(auto_now_add=True)
    total_dependencies = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)
    
    def __str__(self):
        return f"Scan {self.id} by {self.user.username} on {self.scan_date.strftime('%Y-%m-%d')}"

class Vulnerability(models.Model):
    report = models.ForeignKey(ScanReport, on_delete=models.CASCADE, related_name='vulnerabilities')
    library_name = models.CharField(max_length=255)
    version = models.CharField(max_length=50)
    cve_id = models.CharField(max_length=50)
    description = models.TextField()
    severity = models.CharField(max_length=20) # Low, Medium, High, Critical
    remediation = models.TextField()

    def __str__(self):
        return f"{self.cve_id} in {self.library_name} ({self.version})"
