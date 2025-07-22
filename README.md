# 🔍 Brutalyze CLI

**Brutalyze** is a command-line tool that analyzes SSH authentication logs (`auth.log`) to detect failed login attempts, brute-force attacks, and blacklisted IP activity. It exports detailed reports and alerts to CSV, JSON, and TXT files.

---

## 📦 Features

- 🔐 Detects failed SSH login attempts
- 🚨 Identifies brute-force attempts (custom threshold + time window)
- 🔴 Flags blacklisted IPs (from `blacklist.txt`)
- 🌍 Fetches IP geolocation info
- 📁 Exports results to:
  - `report_<timestamp>.csv`
  - `report_<timestamp>.json`
  - `alerts_<timestamp>.txt`
- ⚙️ Command-line arguments for flexibility

---

## 🖥️ CLI Usage

```bash
python brutalyze.py --log sample_auth.log --threshold 5 --window 1
```

| Option         | Description                                  |
|----------------|----------------------------------------------|
| `--log`        | Path to the log file                         |
| `--threshold`  | Number of failed attempts to flag brute-force|
| `--window`     | Time window in minutes for brute-force check |

---

## 📝 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 📁 Files Included

- `brutalyze.py` – main analyzer script
- `sample_auth.log` – sample Linux log file
- `blacklist.txt` – list of flagged IPs
- `requirements.txt` – dependencies

---

## 📤 Output Example

```
🔐 Failed Login Attempts by IP:
  192.168.1.10 → 5 attempts

🚨 Suspected Brute-force IPs:
  ⚠️ 192.168.1.10

🔴 Blacklisted IPs Detected in Logs:
  🚫 192.168.1.10

📄 Alerts saved to: alerts_2025-07-22_15-30-00.txt
📁 Reports exported:
  → report_2025-07-22_15-30-00.csv
  → report_2025-07-22_15-30-00.json
```

---

## 🌐 Coming Soon

A web-based version where users can upload log files via browser and get instant analysis!

---

## 🔗 GitHub

**Star this repo** if you find it useful:  
👉 [https://github.com/ubiiii/brutalyze-cli](https://github.com/ubiiii/brutalyze-cli)
