# app/urls.py
from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static

app_name = 'app'
urlpatterns = [
    path('', views.home, name='home'),
    path('check_ip/', views.check_ip, name='check_ip'),
    path('check_ip_virustotal/', views.check_ip_virustotal, name='check_ip_virustotal'),
    path('check_domain_virustotal/', views.check_domain_virustotal, name='check_domain_virustotal'),
    path('check_url_virustotal/', views.check_url_virustotal, name='check_url_virustotal'),
    path('check_hash_virustotal/', views.check_hash_virustotal, name='check_hash_virustotal'),
    path('check_user_agent/', views.check_user_agent, name='check_user_agent'),
    path("healthz/", views.healthz, name="healthz"),
    path('send_ip_statistics/', views.save_ip_statistics, name='send_ip_statistics'),
    path('send_ip_vt_statistics/', views.save_ip_vt_statistics, name='send_ip_vt_statistics'),
    path('send_domain_statistics/', views.save_domain_statistics, name='send_domain_statistics'),
    path('send_user_agent_statistics/', views.save_user_agent_statistics, name='send_user_agent_statistics'),
    path('send_url_statistics/', views.save_url_statistics, name='send_url_statistics'),
    path('send_hash_statistics/', views.save_hash_statistics, name='send_hash_statistics'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
