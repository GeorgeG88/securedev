# SportShop Extreme-Input REST Tester (Tool)

## What it does
Automates testing of every REST endpoint with **extreme inputs** (wrong types like `"George"` for numbers, `-1` for positive ints, huge values, empty strings, long strings, nulls, missing fields, etc.) and flags suspicious behavior:
- 5xx errors
- error text that looks like stack traces / SQL errors
- unexpected success on obviously invalid input
- slow responses

## Requirements
- Python 3.10+ (Windows OK)
- Your SportShop server running (default: http://localhost:4000)
- Seeded admin exists (default creds in `endpoints_sportshop.json`)

## Install
From this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run
Start your server first, then:

```powershell
.\.venv\Scripts\python.exe fuzz_tool.py --base-url http://localhost:4000 --out fuzz_report.json
```

Optional overrides:

```powershell
.\.venv\Scripts\python.exe fuzz_tool.py --admin-email admin@sportshop.test --admin-password AdminPass123! --out report.json
```

The tool will auto-register a random customer user, login as customer + admin, create a baseline product + order, then run fuzz cases.

## Output
- `fuzz_report.json` contains every test case and the subset flagged as “interesting”.
