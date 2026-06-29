# Open Redirect Log Detector

A Python tool for detecting possible open redirect attempts inside Apache/Nginx-style web access logs.

The script scans log files for common redirect parameters, encoded URLs, suspicious schemes, route-based redirect payloads, and common bypass patterns used in open redirect testing.

## Features

* Detects common open redirect parameters
* Supports Apache combined log format
* Supports normal and URL-encoded payloads
* Detects `http://`, `https://`, `//`, and encoded URL forms
* Detects suspicious schemes like `javascript:`
* Detects route-based payloads such as `/redirect/{payload}` and `/out/{payload}`
* Supports `.gz` compressed log files
* Can filter only successful redirect responses such as `301`, `302`, `303`, `307`, and `308`
* Can ignore trusted internal domains using an allowlist

## Common Parameters Detected

Examples of parameters checked by the script:

```text
next
url
target
rurl
dest
destination
redir
redirect
redirect_url
redirect_uri
return
return_url
returnTo
return_to
continue
callback
callback_url
goto
forward_url
jump_url
origin
originUrl
checkout_url
image_url
```

## Installation

No external Python packages are required.

```bash
git clone https://github.com/yourname/open-redirect-log-detector.git
cd open-redirect-log-detector
```

Make the script executable:

```bash
chmod +x detect_open_redirect_all.py
```

## Usage

Scan one log file:

```bash
python3 detect_open_redirect_all.py access.log
```

Save results to a file:

```bash
python3 detect_open_redirect_all.py access.log > open_redirect_hits.txt
```

Scan multiple log files:

```bash
python3 detect_open_redirect_all.py *.log
```

Scan compressed logs:

```bash
python3 detect_open_redirect_all.py *.gz
```

Show only successful redirect responses:

```bash
python3 detect_open_redirect_all.py --only-30x access.log
```

Ignore trusted internal domains:

```bash
python3 detect_open_redirect_all.py --allow-domain victim.com access.log
```

## Example Test

Create a test log:

```bash
cat > test.log << 'EOF'
178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /redirect?next=https://evil.com HTTP/1.1" 302 2270 "-" "Mozilla/5.0"
178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /out/https://evil.com HTTP/1.1" 302 2270 "-" "Mozilla/5.0"
178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /login?return_url=https%3A%2F%2Fevil.com HTTP/1.1" 302 2270 "-" "Mozilla/5.0"
EOF
```

Run the detector:

```bash
python3 detect_open_redirect_all.py test.log
```

## Example Output

```text
========================================================================================================================
FILE:    access.log
LINE:    1
IP:      178.78.113.5
TIME:    18/Apr/2023:19:42:00 +0000
STATUS:  302
SOURCE:  request-target
TYPE:    redirect parameter
PARAM:   next
HOST:    evil.com
VALUE:   https://evil.com
REASON:  absolute external URL
RAW:     178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /redirect?next=https://evil.com HTTP/1.1" 302 2270 "-" "Mozilla/5.0"
```

## What This Tool Detects

The script looks for suspicious redirect behavior such as:

```text
/login?next=https://evil.com
/redirect?url=http://attacker.com
/callback?redirect_uri=https%3A%2F%2Fevil.com
/logout?return_url=//evil.com
/out/https://evil.com
/redirect/https://evil.com
```

It also detects common bypass patterns such as:

```text
//attacker.com
http:attacker.com
https:attacker.com
https://example.com@attacker.com
javascript:alert(1)
```

## Recommended SOC Usage

This script is useful during:

* Web log analysis
* SOC alert triage
* Threat hunting
* Bug bounty log review
* Incident response
* Detection engineering validation

A strong open redirect indicator usually contains:

```text
redirect parameter + external URL + 30x status code
```

## Limitations

This tool detects possible open redirect attempts from logs. It does not prove that the vulnerability is exploitable by itself.

To confirm the vulnerability, analysts should manually validate whether the application actually returns a redirect response with a `Location` header pointing to an external domain.

## Security Notice

Use this tool only on logs and systems you own or are authorized to analyze.

## License

MIT License
