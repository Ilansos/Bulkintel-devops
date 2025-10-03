from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls import handler400, handler403, handler404, handler500

urlpatterns = [
    path('administration/', admin.site.urls),
    path('', include('auth_app.urls')),
    path('', include('app.urls')),  # Adjust this line if your app is named differently
    path('', include('analytics.urls')),  # Include analytics URLs
]
# Serving static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Error handlers
handler400 = "auth_app.views.error_400"   # Bad Request
handler403 = "auth_app.views.error_403"   # Permission Denied
handler404 = "auth_app.views.error_404"   # Page Not Found
handler500 = "auth_app.views.error_500"   # Server Error
