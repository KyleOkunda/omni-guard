import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.utils import timezone
import datetime
from .models import Agent, AgentHeartbeat
from .logic import analyze_hooks

@csrf_exempt
def heartbeat_api(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            agent_id = data.get('agent_id')
            hostname = data.get('hostname', 'Unknown')
            hooks = data.get('active_hooks_list', [])
            
            if not agent_id:
                return JsonResponse({'error': 'agent_id required'}, status=400)
                
            # specific logic to find or create agent
            agent, created = Agent.objects.get_or_create(agent_id=agent_id, defaults={'hostname': hostname})
            
            # Update generic info
            if hostname != 'Unknown':
                agent.hostname = hostname
            agent.ip_address = request.META.get('REMOTE_ADDR')
            
            # Analyze Risk
            is_risk, suspicious = analyze_hooks(hooks)
            
            # Record Heartbeat
            AgentHeartbeat.objects.create(
                agent=agent,
                active_hooks_json=json.dumps(hooks),
                risk_score=len(suspicious)
            )
            
            # Update Status
            if not agent.is_active: 
                # If was disconnected, maybe re-connect?
                # For now let's respect the disconnect, unless it's a "re-enrollment".
                # But for MVP, let's auto-activate on heartbeat if it was just offline
                pass
            
            if is_risk:
                agent.status = 'Risk'
            else:
                agent.status = 'Online'
            
            # If forcibly disconnected, keep it that way? 
            # The prompt says "Force Disconnect button updates status in DB".
            # So if DB says "Disconnected" (custom status), maybe we ignore update?
            # Let's assume Force Disconnect sets is_active=False.
            if agent.is_active:
                agent.save()
            
            return JsonResponse({'status': 'ok', 'risk_detected': is_risk})
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
            
    return JsonResponse({'error': 'POST required'}, status=405)

@login_required
def endpoint_dashboard_view(request):
    # Update statuses first (Offline Check)
    threshold = timezone.now() - datetime.timedelta(minutes=5)
    
    # Filter active agents, check if they are timed out
    agents = Agent.objects.filter(is_active=True)
    for agent in agents:
        if agent.last_heartbeat < threshold:
            if agent.status != 'Risk': # Don't overwrite Risk with Offline
                agent.status = 'Offline'
                agent.save()

    all_agents = Agent.objects.all().order_by('-last_heartbeat')
    return render(request, 'endpoint_monitor/dashboard.html', {'agents': all_agents})

@login_required
def disconnect_agent_view(request, agent_id):
    agent = get_object_or_404(Agent, id=agent_id)
    agent.is_active = False
    agent.status = 'Disconnected'
    agent.save()
    return redirect('endpoint_dashboard')
