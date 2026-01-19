from django.urls import path
from . import views

urlpatterns = [
    path('infrastructure-monitor/', views.scan_network_view, name='scan_network'),
    path('infrastructure-monitor/history/', views.report_list_view, name='network_report_list'),
    path('infrastructure-monitor/report/<int:report_id>/', views.report_detail_view, name='network_report_detail'),
]
