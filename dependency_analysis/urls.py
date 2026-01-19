from django.urls import path
from . import views

urlpatterns = [
    path('analyze-code/', views.upload_dependency_view, name='upload_dependency'),
    path('analyze-code/history/', views.report_list_view, name='dependency_report_list'),
    path('analyze-code/report/<int:report_id>/', views.report_detail_view, name='dependency_report_detail'),
]
