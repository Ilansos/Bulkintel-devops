from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods, require_safe
from django.views.decorators.csrf import csrf_protect
from .utils import extract_ips, abuse_ipdb_logic, virustotal_logic, get_domain_report, extract_domains, get_user_agent_info, scan_url_virustotal, scan_hashes_logic, log_ip_events, log_domain_events, log_url_events, log_ua_events, log_hash_events, extract_hashes, check_db, check_cache
from django.shortcuts import render
from analytics.models import IpLookup, DomainLookup, UrlLookup, UserAgentLookup, Source
import logging
import sys
from django.views.decorators.cache import never_cache

logging.basicConfig(stream=sys.stdout, 
                    level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BAD_INPUT_ERROR = "Bad input"

@require_http_methods(["GET"])
def home(request):
    return render(request, 'app/index.html')

@require_http_methods(["POST"])
@csrf_protect
def check_ip(request):
    if request.method == "POST":
        ip_data = request.POST.get('ip_data', '')
        ips = extract_ips(ip_data)
        results = abuse_ipdb_logic(ips)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_ip_virustotal(request):
    if request.method == "POST":
        ip_data = request.POST.get('ip_data', '')
        ips = extract_ips(ip_data)
        results = virustotal_logic(ips)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_domain_virustotal(request):
    if request.method == "POST":
        domains_data = request.POST.get('ip_data', '')
        domains = extract_domains(domains_data)
        results = get_domain_report(domains)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_user_agent(request):
    if request.method == "POST":
        user_agents_data_data = request.POST.get('ip_data', '')
        user_agents_raw = extract_domains(user_agents_data_data)
        results = get_user_agent_info(user_agents_raw)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["POST"])
@csrf_protect
def check_url_virustotal(request):
    if request.method == "POST":
        urls_data_data = request.POST.get('ip_data', '')
        urls_to_scan = extract_domains(urls_data_data)
        results = scan_url_virustotal(urls_to_scan)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON
    
@require_http_methods(["POST"])
@csrf_protect
def check_hash_virustotal(request):
    if request.method == "POST":
        hash_data = request.POST.get('ip_data', '')
        results = scan_hashes_logic(hash_data)
        return JsonResponse({'results': results}, safe=False)  # Return data as JSON

@require_http_methods(["GET"])
@never_cache
def healthz(request):
    db = check_db("default")
    cache_status = check_cache("default")

    all_ok = db["ok"] and cache_status["ok"]
    status_code = 200 if all_ok else 503

    payload = {
        "status": "ok" if all_ok else "degraded",
        "checks": {
            "database": db,
            "cache": cache_status,
        },
    }
    return JsonResponse(payload, status=status_code)

@require_http_methods(["POST"])
@csrf_protect
def save_ip_statistics(request):
    if request.method == "POST":
        try:
            ip_data = request.POST.get('ip_data', '')
            ips = extract_ips(ip_data)
            log_ip_events(ips, request.user, Source.IP)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': 'internal'}, status=500)
        
@require_http_methods(["POST"])
@csrf_protect
def save_ip_vt_statistics(request):
    if request.method == "POST":
        try:
            ip_data = request.POST.get('ip_data', '')
            ips = extract_ips(ip_data)
            log_ip_events(ips, request.user, Source.IP)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': 'internal'}, status=500)
        
@require_http_methods(["POST"])
@csrf_protect
def save_domain_statistics(request):
    if request.method == "POST":
        try:
            domains_data = request.POST.get('ip_data', '')
            domains = extract_domains(domains_data)
            log_domain_events(domains, request.user, Source.VT_DOMAIN)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=500)

@require_http_methods(["POST"])
@csrf_protect
def save_user_agent_statistics(request):
    if request.method == "POST":
        try:
            user_agents_data_data = request.POST.get('ip_data', '')
            user_agents_raw = extract_domains(user_agents_data_data)
            log_ua_events(user_agents_raw, request.user, Source.UA)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': 'internal'}, status=500)

@require_http_methods(["POST"])
@csrf_protect
def save_url_statistics(request):
    if request.method == "POST":
        try:
            urls_data_data = request.POST.get('ip_data', '')
            urls_to_scan = extract_domains(urls_data_data)
            log_url_events(urls_to_scan, request.user, Source.VT_URL)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': 'internal'}, status=500)
        
@require_http_methods(["POST"])
@csrf_protect
def save_hash_statistics(request):
    if request.method == "POST":
        try:
            hash_data = request.POST.get('ip_data', '')
            hashes = extract_hashes(hash_data)
            log_hash_events(hashes, request.user, Source.VT_HASH)
            return JsonResponse({'ok': True}, status=200)
        except ValueError as e:  # e.g., bad input
            logger.error(f"ValueError: {e}")
            return JsonResponse({'ok': False, 'error': BAD_INPUT_ERROR}, status=400)
        except Exception as e:
            logger.error(f"Exception: {e}")
            return JsonResponse({'ok': False, 'error': 'internal'}, status=500)