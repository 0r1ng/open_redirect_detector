#!/usr/bin/env python3
import sys
import re
import gzip
import argparse
from urllib.parse import unquote_plus, urlsplit, parse_qsl

REDIRECT_PARAMS = {
    "next", "url", "target", "rurl", "dest", "destination",
    "redir", "redirect_uri", "redirect_url", "redirect",
    "view", "to", "image_url", "go", "return", "returnto",
    "return_to", "checkout_url", "continue", "return_path",
    "success", "data", "qurl", "login", "logout", "ext",
    "clickurl", "goto", "rit_url", "forward_url", "forward",
    "pic", "callback", "callback_url", "jump", "jump_url",
    "originurl", "origin", "desturl", "u", "u1", "page",
    "action", "action_url", "sp_url", "service", "recurl",
    "uri", "allinurl", "q", "link", "src", "linkaddress",
    "location", "burl", "request", "backurl", "redirecturl",
    "returnurl", "return_url", "returnpath", "returnpath",
    "back", "back_url", "continue_url", "next_url", "out",
    "external", "external_url", "link_url", "file_url"
}

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[0-9.]+$',
    re.IGNORECASE
)

PARAM_RE = re.compile(
    r'(?i)(?:^|[?&;\s"\'])'
    r'([a-z0-9_.-]{1,80})='
    r'([^&\s"\'<>]*)'
)

RAW_SPECIAL_RE = re.compile(
    r'(?i)(allinurl:|@)(https?://|//|https?%3a%2f%2f|http%3a%2f%2f)'
)

ROUTE_RE = re.compile(
    r'(?i)/(redirect|out)/([^?\s"\']+)'
)

CGI_RAW_RE = re.compile(
    r'(?i)/cgi-bin/redirect\.cgi\?([^ \t\r\n"\']+)'
)

def open_file(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "r", errors="ignore")

def decode_many(value, rounds=6):
    value = value.replace("\\x3a", "%3a").replace("\\x2f", "%2f")
    for _ in range(rounds):
        new = unquote_plus(value)
        if new == value:
            break
        value = new
    return value

def compact(value):
    return re.sub(r'[\x00-\x20]+', '', value.lower())

def get_host(value):
    v = decode_many(value).strip().strip('"').strip("'")
    v = v.replace("\\", "/")

    if v.startswith("//"):
        v = "http:" + v

    try:
        host = urlsplit(v).netloc.lower()
        if "@" in host:
            host = host.split("@")[-1]
        return host.split(":")[0]
    except Exception:
        return ""

def allowed_host(host, allowed_domains):
    if not allowed_domains:
        return False

    host = host.lower().strip(".")
    for domain in allowed_domains:
        d = domain.lower().strip(".")
        if host == d or host.endswith("." + d):
            return True
    return False

def suspicious_value(value, allowed_domains):
    raw = value.strip()
    dec = decode_many(raw).strip().strip('"').strip("'")
    slash_fixed = dec.replace("\\", "/")
    low = slash_fixed.lower()
    small = compact(slash_fixed)

    reasons = []

    if low.startswith("http://") or low.startswith("https://"):
        reasons.append("absolute external URL")

    if low.startswith("//") or low.startswith("///"):
        reasons.append("scheme-relative external URL")

    if raw.startswith("\\\\") or dec.startswith("\\\\"):
        reasons.append("backslash scheme-relative bypass")

    if small.startswith("http:") and not small.startswith("http://"):
        reasons.append("http scheme without // bypass")

    if small.startswith("https:") and not small.startswith("https://"):
        reasons.append("https scheme without // bypass")

    if small.startswith("javascript:"):
        reasons.append("javascript scheme payload")

    if raw.lower().startswith(("/%0a/", "/%0d/", "/%09/", "/+/", "///")):
        reasons.append("encoded slash/control bypass")

    if low.startswith(("/\n/", "/\r/", "/\t/", "/+/")):
        reasons.append("decoded slash/control bypass")

    if "%00" in raw.lower() or "\x00" in dec:
        reasons.append("null-byte bypass")

    if re.search(r'(?i)%0a|%0d|%09', raw):
        reasons.append("encoded control character")

    if low.startswith("@http://") or low.startswith("@https://"):
        reasons.append("@ external URL payload")

    host = get_host(dec)

    if host and allowed_domains and allowed_host(host, allowed_domains):
        return [], dec, host

    if host and allowed_domains and not allowed_host(host, allowed_domains):
        reasons.append("external host not in allowed-domain list")

    if "@" in low and (low.startswith("http://") or low.startswith("https://")):
        reasons.append("userinfo @ domain-bypass pattern")

    if "://" in low and any(x in low for x in ["%00", "%0a", "%0d", "%09"]):
        reasons.append("encoded terminator/control domain-bypass pattern")

    return sorted(set(reasons)), dec, host

def parse_log_line(line):
    m = COMBINED_RE.match(line)
    if not m:
        return {
            "ip": "",
            "time": "",
            "request": line.strip(),
            "status": "",
            "target": line.strip(),
            "referer": "",
            "agent": "",
        }

    request = m.group("request")
    rm = REQUEST_RE.match(request)

    target = request
    if rm:
        target = rm.group("target")

    return {
        "ip": m.group("ip"),
        "time": m.group("time"),
        "request": request,
        "status": m.group("status"),
        "target": target,
        "referer": m.group("referer"),
        "agent": m.group("agent"),
    }

def scan_params(text, source_name, allowed_domains):
    findings = []
    decoded_text = decode_many(text)

    for m in PARAM_RE.finditer(decoded_text):
        name = m.group(1).lower()
        value = m.group(2)

        if name not in REDIRECT_PARAMS:
            continue

        reasons, decoded_value, host = suspicious_value(value, allowed_domains)
        if reasons:
            findings.append({
                "source": source_name,
                "type": "redirect parameter",
                "param": name,
                "value": decoded_value,
                "host": host,
                "reasons": reasons,
            })

    try:
        query = urlsplit(decoded_text).query
        for name, value in parse_qsl(query, keep_blank_values=True):
            key = name.lower()
            if key not in REDIRECT_PARAMS:
                continue

            reasons, decoded_value, host = suspicious_value(value, allowed_domains)
            if reasons:
                findings.append({
                    "source": source_name,
                    "type": "parsed query parameter",
                    "param": key,
                    "value": decoded_value,
                    "host": host,
                    "reasons": reasons,
                })
    except Exception:
        pass

    return findings

def scan_routes(text, source_name, allowed_domains):
    findings = []
    decoded_text = decode_many(text)

    for m in ROUTE_RE.finditer(decoded_text):
        route = m.group(1)
        payload = m.group(2)
        reasons, decoded_value, host = suspicious_value(payload, allowed_domains)
        if reasons:
            findings.append({
                "source": source_name,
                "type": f"/{route}/payload",
                "param": route,
                "value": decoded_value,
                "host": host,
                "reasons": reasons,
            })

    for m in CGI_RAW_RE.finditer(decoded_text):
        payload = m.group(1)
        reasons, decoded_value, host = suspicious_value(payload, allowed_domains)
        if reasons:
            findings.append({
                "source": source_name,
                "type": "/cgi-bin/redirect.cgi raw payload",
                "param": "raw-query",
                "value": decoded_value,
                "host": host,
                "reasons": reasons,
            })

    stripped = decoded_text.strip()
    if stripped.startswith("/"):
        payload = stripped[1:]
        reasons, decoded_value, host = suspicious_value(payload, allowed_domains)
        if reasons:
            findings.append({
                "source": source_name,
                "type": "/{payload}",
                "param": "path-payload",
                "value": decoded_value,
                "host": host,
                "reasons": reasons,
            })

    if RAW_SPECIAL_RE.search(decoded_text):
        findings.append({
            "source": source_name,
            "type": "raw special payload",
            "param": "raw",
            "value": decoded_text,
            "host": "",
            "reasons": ["allinurl: or @ external URL pattern"],
        })

    return findings

def unique_findings(findings):
    seen = set()
    result = []

    for f in findings:
        key = (
            f.get("source", ""),
            f.get("type", ""),
            f.get("param", ""),
            f.get("value", ""),
            ",".join(f.get("reasons", [])),
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(f)

    return result

def print_finding(filename, line_no, meta, finding, raw):
    print("=" * 120)
    print(f"FILE:    {filename}")
    print(f"LINE:    {line_no}")
    print(f"IP:      {meta.get('ip') or '-'}")
    print(f"TIME:    {meta.get('time') or '-'}")
    print(f"STATUS:  {meta.get('status') or '-'}")
    print(f"SOURCE:  {finding['source']}")
    print(f"TYPE:    {finding['type']}")
    print(f"PARAM:   {finding['param']}")
    print(f"HOST:    {finding['host'] or '-'}")
    print(f"VALUE:   {finding['value']}")
    print(f"REASON:  {', '.join(finding['reasons'])}")
    print(f"RAW:     {raw.rstrip()}")

def main():
    parser = argparse.ArgumentParser(description="Broad open redirect detector for Apache/Nginx style logs.")
    parser.add_argument("logs", nargs="+", help="Log files. Supports .gz. Use - for stdin.")
    parser.add_argument("--only-30x", action="store_true", help="Only show 301, 302, 303, 307, 308 responses.")
    parser.add_argument("--allow-domain", action="append", default=[], help="Internal allowed domain. Example: --allow-domain victim.com")
    args = parser.parse_args()

    redirect_statuses = {"301", "302", "303", "307", "308"}

    for filename in args.logs:
        try:
            with open_file(filename) as f:
                for line_no, line in enumerate(f, 1):
                    meta = parse_log_line(line)

                    if args.only_30x and meta.get("status") not in redirect_statuses:
                        continue

                    sources = [
                        ("request-target", meta.get("target", "")),
                        ("referer", meta.get("referer", "")),
                        ("full-line", line),
                    ]

                    findings = []

                    for source_name, text in sources:
                        if not text or text == "-":
                            continue

                        findings.extend(scan_params(text, source_name, args.allow_domain))
                        findings.extend(scan_routes(text, source_name, args.allow_domain))

                    findings = unique_findings(findings)

                    for finding in findings:
                        print_finding(filename, line_no, meta, finding, line)

        except FileNotFoundError:
            print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        except PermissionError:
            print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)

if __name__ == "__main__":
    main()
