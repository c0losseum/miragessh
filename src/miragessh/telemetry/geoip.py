"""
MirageSSH - IP Geolocation & Threat Intelligence Resolver
Enriches attacker IPs with geographical location, country flags, ISP, and ASN.
Includes local caching and RFC1918 private network handling.
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from typing import Dict, Optional

logger = logging.getLogger("miragessh.geoip")


@dataclass
class GeoIPData:
    ip: str
    country: str = "Unknown"
    country_code: str = "??"
    region: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    org: str = "Unknown"
    asn: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    is_private: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class GeoIPResolver:
    """Resolves IP addresses using free GeoIP services with in-memory caching."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._cache: Dict[str, GeoIPData] = {}

    def is_private_ip(self, ip: str) -> bool:
        """Checks if IP belongs to private/loopback RFC1918 or link-local ranges."""
        if ip in ["127.0.0.1", "::1", "localhost"]:
            return True
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        return False

    def lookup(self, ip: str) -> GeoIPData:
        """Resolves IP and returns GeoIPData."""
        if not ip:
            return GeoIPData(ip="unknown")

        if ip in self._cache:
            return self._cache[ip]

        if self.is_private_ip(ip):
            geo = GeoIPData(
                ip=ip,
                country="Internal / Private Network",
                country_code="LAN",
                region="Private",
                city="Local Lab",
                isp="Private Infrastructure",
                org="Internal Host",
                asn="AS0",
                latitude=0.0,
                longitude=0.0,
                is_private=True,
            )
            self._cache[ip] = geo
            return geo

        if not self.enabled:
            return GeoIPData(ip=ip)

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "MirageSSH-Honeypot/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success":
                geo = GeoIPData(
                    ip=ip,
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "??"),
                    region=data.get("regionName", "Unknown"),
                    city=data.get("city", "Unknown"),
                    isp=data.get("isp", "Unknown"),
                    org=data.get("org", "Unknown"),
                    asn=data.get("as", "Unknown"),
                    latitude=float(data.get("lat", 0.0)),
                    longitude=float(data.get("lon", 0.0)),
                    is_private=False,
                )
                self._cache[ip] = geo
                return geo
        except Exception as e:
            logger.debug(f"GeoIP resolution failed for {ip}: {e}")

        # Fallback on network failure
        fallback = GeoIPData(ip=ip, country="Unknown", country_code="??")
        self._cache[ip] = fallback
        return fallback
