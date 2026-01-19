from django.db import models
from django.contrib.auth.models import User

class NetworkScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255) # Domain or IP
    scan_date = models.DateTimeField(auto_now_add=True)
    score = models.FloatField()
    grade = models.CharField(max_length=2) # A, B, C, D, E, F
    
    def __str__(self):
        return f"Scan of {self.target} ({self.grade})"

class ExposedPort(models.Model):
    scan = models.ForeignKey(NetworkScan, on_delete=models.CASCADE, related_name='exposed_ports')
    port_number = models.IntegerField()
    service_name = models.CharField(max_length=100)
    is_risk = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.port_number}/{self.service_name}"
