import ipaddress
import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

API_URL = "https://reputation.example.com/v1/ip/{}"
REQUEST_TIMEOUT = 5
MAX_RETRIES = 4
RATE_LIMIT = 4
last_request = 0



# Logging
logger = logging.getLogger(__name__)

def log_event(alert_id, event):
    logger.info(json.dumps({"alert_id": alert_id, "event": event}))


# Validate alert
def validate_alert(alert):
    if not isinstance(alert, dict):
        raise ValueError("Invalid alert")

    if not all(
        isinstance(alert.get(field), str) and alert[field].strip()
        for field in ("alert_id", "title", "severity")
    ):
        raise ValueError("Missing or invalid alert fields")

    if not isinstance(alert.get("entities"), dict):
        raise ValueError("Invalid entities")

    ips = alert["entities"].get("ips")

    if not isinstance(ips, list) or not all(isinstance(ip,str) for ip in ips):
        raise ValueError("Invalid IP list")




# Clean IP address
def clean_ips(ips):
    valid, skipped, seen = [], [], set()

    for value in ips:
        if not isinstance(value, str):
            skipped.append({"value": value, "reason": "invalid"})
            continue

        value = value.strip()

        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            skipped.append({"value": value, "reason":"invalid"})
            continue

        if str(ip) in seen:
            continue
        seen.add(str(ip))

        if ip in ipaddress.ip_network("2001:db8::/32"):
            reason ="reserved"
        elif ip.is_loopback:
            reason = "loopback"
        elif ip.is_private:
            reason = "private"
        elif not ip.is_global:
            reason ="reserved"
        else:
            valid.append(str(ip))
            continue

        skipped.append({"value": value, "reason": reason})

    return valid, skipped


# Limit requests to 4 per second
def rate_limit():
    global last_request

    wait = 1 / RATE_LIMIT - (time.monotonic() - last_request)
    if wait > 0:
        time.sleep(wait)

    last_request = time.monotonic()


#Look up IP reputation
def lookup_ip(ip, api_key):
    for attempt in range(MAX_RETRIES):
        try:
            rate_limit()

            response = requests.get(
                API_URL.format(ip), headers={"X-Api-Key": api_key}, timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 404:
                return {"ip": ip, "status": "unknown"}

            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "status": "ok",
                    "score": data["score"],
                    "categories": data["categories"],
                    "malicious": data["score"] >= 70,
                    "country": data["country"],
                }

            if response.status_code != 429 and response.status_code < 500:
                return {"ip": ip, "status": "error"}

            if attempt < MAX_RETRIES - 1:
                retry_after = response.headers.get("Retry-After")

                try:
                    delay = float(retry_after)
                except (TypeError, ValueError):
                    try:
                        delay = (
                            parsedate_to_datetime(retry_after)
                            - datetime.now(timezone.utc)
                        ).total_seconds()
                    except (TypeError, ValueError):
                        delay = 2**attempt

                time.sleep(max(0, delay) + random.uniform(0, 0.5))

        except requests.RequestException:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2**attempt + random.uniform(0, 0.5))

    return {"ip": ip, "status": "error", "message": "Retries exhausted"}
