from django.contrib import admin

# Register your models here.
from .models import IpLookup, DomainLookup, UrlLookup, UserAgentLookup, HashLookup
admin.site.register(IpLookup)
admin.site.register(DomainLookup)
admin.site.register(UrlLookup)
admin.site.register(UserAgentLookup)
admin.site.register(HashLookup)