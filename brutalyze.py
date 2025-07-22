import re
from collections import defaultdict
from datetime import datetime, timedelta
import csv
import json
import os
import requests
import time
import argparse

# === ARGPARSE CONFIG ===
parser = argparse.ArgumentParser(description="Brutalyze: SSH log analyzer with brute-force detection.")
parser.add_argument("--log", type=str, default="./sample_auth.log", help="Path to the log file")
parser.add_argument("--threshold", type=int, default=5, help="Failed attempts threshold for brute-force detection")
parser.add_argument("--window", type=int, default=1, help="Time window in minutes for brute-force detection")

args = parser.parse_args()

# Use CLI args instead of hardcoded values
LOG_FILE = args.log
BRUTE_THRESHOLD = args.threshold
TIME_WINDOW = timedelta(minutes=args.window)
ENCODING = "utf-8"

# === IP Geolocation ===
def get_ip_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,query", timeout=5)
        data = response.json()
        if data["status"] == "success":
            return {
                "ip": ip,
                "country": data.get("country", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", "")
            }
        elif data.get("message") == "private range":
            return {
                "ip": ip,
                "country": "Private IP",
                "region": "-",
                "city": "-"
            }
        else:
            return {"ip": ip, "country": "", "region": "", "city": ""}
    except:
        return {"ip": ip, "country": "", "region": "", "city": ""}

# === REGEX PATTERN ===
FAILED_LOGIN_REGEX = re.compile(
    r"(?P<date>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd.*Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>[\d\.]+)"
)

# === STORAGE ===
failed_attempts_by_ip = defaultdict(int)
failed_attempts_by_user = defaultdict(int)
attempt_timestamps = defaultdict(list)
raw_entries = []

def parse_datetime(date_str):
    return datetime.strptime(date_str + " " + str(datetime.now().year), "%b %d %H:%M:%S %Y")

# === PARSE LOG ===
with open(LOG_FILE, "r", encoding=ENCODING, errors="ignore") as f:
    for line in f:
        match = FAILED_LOGIN_REGEX.search(line)
        if match:
            date_str = match.group("date")
            ip = match.group("ip")
            user = match.group("user")
            dt = parse_datetime(date_str)
            failed_attempts_by_ip[ip] += 1
            failed_attempts_by_user[user] += 1
            attempt_timestamps[ip].append(dt)
            raw_entries.append((dt, ip, user))

# === BRUTE-FORCE DETECTION ===
brute_force_ips = []
for ip, times in attempt_timestamps.items():
    times.sort()
    for i in range(len(times) - BRUTE_THRESHOLD + 1):
        if times[i + BRUTE_THRESHOLD - 1] - times[i] <= TIME_WINDOW:
            brute_force_ips.append(ip)
            break

# === BLACKLIST CHECK ===
BLACKLIST_FILE = "blacklist.txt"
blacklisted_ips = set()
if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, "r") as bl_file:
        for line in bl_file:
            ip = line.strip()
            if ip:
                blacklisted_ips.add(ip)
else:
    print("⚠️  Warning: blacklist.txt not found — skipping blacklist check.")

flagged_blacklist_matches = [ip for ip in failed_attempts_by_ip if ip in blacklisted_ips]

# === ALERT TRIGGERS ===
ALERTS = []
if len(brute_force_ips) >= 3:
    ALERTS.append(f"🚨 {len(brute_force_ips)} brute-force IPs detected")
if flagged_blacklist_matches:
    for ip in flagged_blacklist_matches:
        ALERTS.append(f"🚫 Blacklisted IP found: {ip}")
total_failures = sum(failed_attempts_by_ip.values())
if total_failures >= 20:
    ALERTS.append(f"🔥 High volume of failed logins: {total_failures} total attempts")

# === OUTPUT ===
print("\n🔐 Failed Login Attempts by IP:")
for ip, count in sorted(failed_attempts_by_ip.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ip} → {count} attempts")

print("\n👤 Failed Login Attempts by Username:")
for user, count in sorted(failed_attempts_by_user.items(), key=lambda x: x[1], reverse=True):
    print(f"  {user} → {count} attempts")

print("\n🚨 Suspected Brute-force IPs:")
if brute_force_ips:
    for ip in brute_force_ips:
        print(f"  ⚠️ {ip}")
else:
    print("  No brute-force patterns detected.")

print("\n📅 Sample Entries:")
for dt, ip, user in raw_entries[:5]:
    print(f"  [{dt}] {ip} → {user}")

print("\n🔴 Blacklisted IPs Detected in Logs:")
if flagged_blacklist_matches:
    for ip in flagged_blacklist_matches:
        print(f"  🚫 {ip}")
else:
    print("  No blacklisted IPs found.")

# === TIMESTAMP FOR REPORT NAME ===
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
EXPORT_DIR = "reports"
os.makedirs(EXPORT_DIR, exist_ok=True)
csv_file = os.path.join(EXPORT_DIR, f"report_{timestamp}.csv")
json_file = os.path.join(EXPORT_DIR, f"report_{timestamp}.json")
alert_file = os.path.join(EXPORT_DIR, f"alerts_{timestamp}.txt")

# === GEOLOCATION FETCH ===
print("\n🌍 Fetching geolocation data for IPs...")
ip_geo_data = {}
for ip in failed_attempts_by_ip:
    ip_geo_data[ip] = get_ip_geolocation(ip)
    time.sleep(1.5)

# === CSV EXPORT ===
with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP Address", "Country", "Region", "City", "Failed Attempts", "Brute Force Suspected", "Blacklisted"])
    for ip, count in failed_attempts_by_ip.items():
        geo = ip_geo_data.get(ip, {"country": "", "region": "", "city": ""})
        brute = "YES" if ip in brute_force_ips else "NO"
        blacklisted = "YES" if ip in blacklisted_ips else "NO"
        writer.writerow([ip, geo["country"], geo["region"], geo["city"], count, brute, blacklisted])

# === JSON EXPORT ===
json_data = {
    "summary": {
        "total_failed_ips": len(failed_attempts_by_ip),
        "total_brute_force_ips": len(brute_force_ips)
    },
    "attempts_by_ip": [
        {
            "ip": ip,
            "failed_attempts": count,
            "brute_force": ip in brute_force_ips,
            "location": ip_geo_data[ip]
        }
        for ip, count in failed_attempts_by_ip.items()
    ]
}
with open(json_file, "w", encoding="utf-8") as f:
    json.dump(json_data, f, indent=4)

# === SAVE ALERTS ===
if ALERTS:
    print("\n⚠️ CRITICAL ALERTS:")
    for alert in ALERTS:
        print(f"  {alert}")
    with open(alert_file, "w", encoding="utf-8") as f:
        for alert in ALERTS:
            f.write(alert + "\n")
    print(f"📄 Alerts saved to {alert_file}")
else:
    print("\n✅ No critical alerts.")

print(f"\n📁 Reports exported:")
print(f"  → {csv_file}")
print(f"  → {json_file}")
