from django.db import models
from django.utils import timezone
import datetime

class Agent(models.Model):
    agent_id = models.CharField(max_length=100, unique=True)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    last_heartbeat = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, default='Offline') # Online, Offline, Risk
    is_active = models.BooleanField(default=True) # Soft delete/Disconnect
    
    def is_online(self):
        # Online if heartbeat within last 5 minutes
        return self.last_heartbeat >= timezone.now() - datetime.timedelta(minutes=5)

    def __str__(self):
        return f"{self.hostname} ({self.agent_id})"

class AgentHeartbeat(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='heartbeats')
    timestamp = models.DateTimeField(auto_now_add=True)
    active_hooks_json = models.TextField() # JSON string of active hooks
    risk_score = models.IntegerField(default=0)
    
    def __str__(self):
        return f"Heartbeat from {self.agent.hostname} at {self.timestamp}"
