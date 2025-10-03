from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from .leaderboard import leaderboard

@require_http_methods(["GET"])
@login_required
@csrf_protect
def leaderboard_view(request):
    entity = request.GET.get("entity", "ip")         # ip|domain|url|ua
    period = request.GET.get("period", "day")        # day|week|month
    limit  = min(int(request.GET.get("limit", 20)), 100)
    rows = list(leaderboard(entity, period, limit))
    return JsonResponse({"entity": entity, "period": period, "results": rows})
