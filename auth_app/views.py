from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods, require_safe
from django.contrib.auth import authenticate, login
from django.urls import reverse
from .forms import CustomUserCreationForm
from .models import AllowedEmail
from axes.helpers import get_client_username
from axes.handlers.proxy import AxesProxyHandler
from axes.utils import reset
from django.conf import settings

LOGIN_HTML = "auth_app/login.html"

@require_http_methods(["POST", "GET"])
def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Specify the ModelBackend explicitly
            backend = 'axes.backends.AxesBackend'
            login(request, user, backend=backend)
            return redirect('/')
    else:
        form = CustomUserCreationForm()
    return render(request, 'auth_app/register.html', {'form': form})

@require_safe
def account_locked(request):
    return render(request, 'auth_app/lockout.html')

@require_http_methods(["POST", "GET"])
def custom_login(request):
    if request.user.is_authenticated:
        return redirect(request.GET.get("next", settings.LOGIN_REDIRECT_URL))
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Check if the user is already locked out
        if AxesProxyHandler.is_locked(request):
            return render(request, 'auth_app/lockout.html')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if AllowedEmail.objects.filter(email=user.email).exists():
                # reset(request, get_client_username(request))  # Reset failed attempts on successful login
                login(request, user)
                return redirect('/')
            else:
                return render(request, LOGIN_HTML, {'error': 'This email is not allowed to log in.'})
        else:
            return render(request, LOGIN_HTML, {'error': 'Invalid username or password.'})
    else:
        return render(request, LOGIN_HTML)


def error_400(request, exception):
    return render(request, "auth_app/400.html", status=400)


def error_403(request, exception):
    return render(request, "auth_app/403.html", status=403)


def error_404(request, exception):
    return render(request, "auth_app/404.html", status=404)


def error_500(request):
    # no exception param here!
    return render(request, "auth_app/500.html", status=500)

def csrf_failure(request, reason=""):
    # You can pass the “reason” string into the template if you like
    return render(request, "auth_app/403.html",
                  {"reason": reason},
                  status=403)
