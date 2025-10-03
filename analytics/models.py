from django.db import models
from django.conf import settings

class Source(models.TextChoices):
    ABUSEIPDB = "abuseipdb", "AbuseIPDB"
    IP        = "ip", "IP"
    VT_IP     = "vt_ip", "VirusTotal IP"
    VT_DOMAIN = "vt_domain", "VirusTotal Domain"
    VT_URL    = "vt_url", "VirusTotal URL"
    VT_HASH   = "vt_hash", "VirusTotal Hash"
    UA        = "ua", "User-Agent"

class BaseLookup(models.Model):
    # store a normalized/canonical value here
    value = models.TextField(db_index=True)
    # optional: keep user input for audit/debug
    raw_value = models.TextField(blank=True)

    source = models.CharField(max_length=32, choices=Source.choices, db_index=True)
    user   = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                               on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["value", "created_at"]),
        ]

class IpLookup(BaseLookup):
    ip_version = models.PositiveSmallIntegerField(choices=[(4, "IPv4"), (6, "IPv6")])

class DomainLookup(BaseLookup):
    pass

class UrlLookup(BaseLookup):
    pass

class UserAgentLookup(BaseLookup):
    pass

class HashLookup(BaseLookup):
    pass
