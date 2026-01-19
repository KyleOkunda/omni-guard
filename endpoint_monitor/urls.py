from django.urls import path
from . import views

urlpatterns = [
    path('api/heartbeat/', views.heartbeat_api, name='heartbeat_api'),
    path('endpoint-monitor/', views.endpoint_dashboard_view, name='endpoint_dashboard'),
    path('endpoint-monitor/disconnect/<int:agent_id>/', views.disconnect_agent_view, name='disconnect_agent'),
]
