import argparse
import json
import random
import re
import string
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---- Heuristics that mark a response as "interesting" (potential vuln signal)
SUSPECT_TEXT = [
    "traceback",
    "stack trace",
    "exception",
    "sql",
    "sqlite",
    "prisma",
    "sequelize",
    "psql",
    "postgres",
    "mysql",
    "syntax error",
    "integrity",
    "constraint failed",
]
DEFAULT_TIMEOUT = 10.0

# ---- Extreme value libraries (type confusion + boundaries)
EXTREME_INT = [-1, 0, 1, 2_147_483_647, 9_223_372_036_854_775_807, "George", None]
EXTREME_STR = ["", " ", "\t", "A" * 5000, "George", "Δ" * 2000, "' OR 1=1 --", "<script>alert(1)</script>", None]
EXTREME_ENUM = ["PENDING", "PAID", "SHIPPED", "CANCELLED", "INVALID", "", 123, None]
EXTREME_URL = ["not-a-url", "http://", "https://example.com/" + ("a" * 4000), None]
EXTREME_ARRAY = [[], [{}], [1, "x", None], None]
EXTREME_FLOAT = [-1.0, 0.0, 1.0, 1e308, "NaN", "inf", None]

@dataclass
class CaseResult:
    endpoint: str
    method: str
    url: str
    status: Optional[int]
    elapsed_ms: Optional[int]
    request: Dict[str, Any]
    response_snippet: str
    error: Optional[str]
    interesting: bool
    reason: Optional[str]

def rands(n=10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def safe_snippet(text: str, limit: int = 800) -> str:
    text = text or ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]

def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")

def http_request(method: str, url: str, headers: Dict[str, str], params: Dict[str, Any], json_body: Any, timeout: float) -> Tuple[Optional[requests.Response], Optional[str], Optional[int]]:
    try:
        start = time.time()
        resp = requests.request(method, url, headers=headers, params=params or None, json=json_body, timeout=timeout)
        elapsed_ms = int((time.time() - start) * 1000)
        return resp, None, elapsed_ms
    except Exception as e:
        return None, str(e), None

def mark_interesting(resp: Optional[requests.Response], err: Optional[str], elapsed_ms: Optional[int], sent_invalid: bool) -> Tuple[bool, Optional[str]]:
    if err:
        return True, f"request_error: {err}"
    if resp is None:
        return True, "no_response"
    if resp.status_code >= 500:
        return True, f"server_error_{resp.status_code}"
    body = (resp.text or "").lower()
    if any(s in body for s in SUSPECT_TEXT):
        return True, "suspect_error_text"
    if elapsed_ms is not None and elapsed_ms > 2500:
        return True, f"slow_response_{elapsed_ms}ms"
    # "unexpected success" is a useful signal for bad validation:
    if sent_invalid and resp.status_code < 400:
        return True, f"unexpected_success_{resp.status_code}"
    return False, None

def load_config(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def auth_login(base_url: str, login_path: str, email: str, password: str, token_field: str) -> str:
    url = join_url(base_url, login_path)
    r = requests.post(url, json={"email": email, "password": password}, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if token_field not in data:
        raise RuntimeError(f"Token field '{token_field}' not found in login response")
    return data[token_field]

def auth_register(base_url: str, register_path: str, email: str, password: str) -> None:
    url = join_url(base_url, register_path)
    r = requests.post(url, json={"email": email, "password": password}, timeout=DEFAULT_TIMEOUT)
    # 200/201 ok; 409 means already exists (fine)
    if r.status_code not in (200, 201, 409):
        r.raise_for_status()

def make_auth_header(cfg: Dict[str, Any], token: str) -> Dict[str, str]:
    hname = cfg["auth"]["auth_header"]
    scheme = cfg["auth"].get("auth_scheme", "Bearer")
    return {hname: f"{scheme} {token}"}

def substitute_placeholders(obj: Any, values: Dict[str, Any]) -> Any:
    if isinstance(obj, str):
        # placeholders like "{product_id}"
        m = re.fullmatch(r"\{([a-zA-Z0-9_]+)\}", obj.strip())
        if m:
            key = m.group(1)
            return values.get(key)
        return obj
    if isinstance(obj, list):
        return [substitute_placeholders(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute_placeholders(v, values) for k, v in obj.items()}
    return obj

def build_cases_for_endpoint(ep: Dict[str, Any], baseline: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any], bool]]:
    """
    Returns list of (case_name, mutated_request_parts, sent_invalid_flag)
    mutated_request_parts can include: path_params, query, json
    """
    cases: List[Tuple[str, Dict[str, Any], bool]] = []

    # Baseline (valid) always first
    cases.append(("baseline", {}, False))

    # Fuzz path params
    for pname, pval in (ep.get("path_params") or {}).items():
        for x in EXTREME_INT + EXTREME_STR:
            cases.append((f"path.{pname}={repr(x)}", {"path_params": {pname: x}}, True))

    # Fuzz query params
    for qname, qval in (ep.get("query") or {}).items():
        pool = EXTREME_STR if isinstance(qval, str) else EXTREME_INT
        for x in pool:
            cases.append((f"query.{qname}={repr(x)}", {"query": {qname: x}}, True))
        # numeric-only query fields (page/limit) still get int pool
        if qname in ("page", "limit"):
            for x in EXTREME_INT:
                cases.append((f"query.{qname}={repr(x)}", {"query": {qname: x}}, True))

    # Fuzz JSON body fields (shallow + a few nested patterns)
    body = ep.get("json")
    if isinstance(body, dict):
        # mutate each top-level field
        for k, v in body.items():
            if k == "status":
                pool = EXTREME_ENUM
            elif k in ("priceCents", "stock", "productId", "quantity", "id"):
                pool = EXTREME_INT
            elif k == "imageUrl":
                pool = EXTREME_URL
            elif isinstance(v, str):
                pool = EXTREME_STR
            elif isinstance(v, (int, bool)) or v is None:
                pool = EXTREME_INT
            else:
                pool = EXTREME_STR
            for x in pool:
                cases.append((f"json.{k}={repr(x)}", {"json": {k: x}}, True))

        # Special: missing fields and extra fields
        cases.append(("json.missing_required", {"json_remove_keys": ["name", "description"]}, True))
        cases.append(("json.extra_field", {"json_add": {"__proto__": {"polluted": "yes"}}}, True))

        # Special for orders: items array fuzzing
        if "items" in body:
            cases.append(("json.items=[]", {"json": {"items": []}}, True))
            cases.append(("json.items=null", {"json": {"items": None}}, True))
            cases.append(("json.items.weird_types", {"json": {"items": [1, "x", None]}}, True))
            cases.append(("json.items.big_quantity", {"json": {"items": [{"productId": baseline.get("product_id"), "quantity": 99999999}]}}, True))
            cases.append(("json.items.negative_quantity", {"json": {"items": [{"productId": baseline.get("product_id"), "quantity": -1}]}}, True))
            cases.append(("json.items.string_productId", {"json": {"items": [{"productId": "George", "quantity": 1}]}}, True))

    return cases

def apply_mutation_to_body(ep_body: Optional[Dict[str, Any]], mutation: Dict[str, Any]) -> Any:
    if ep_body is None:
        return None
    body = json.loads(json.dumps(ep_body))  # deep copy

    if "json" in mutation:
        for k, v in mutation["json"].items():
            body[k] = v
    if "json_add" in mutation:
        body.update(mutation["json_add"])
    if "json_remove_keys" in mutation:
        for k in mutation["json_remove_keys"]:
            body.pop(k, None)
    return body

def main():
    ap = argparse.ArgumentParser(description="Extreme-input REST tester (SportShop-ready)")
    ap.add_argument("--config", default="endpoints_sportshop.json", help="Path to endpoint config JSON")
    ap.add_argument("--base-url", default=None, help="Override base URL, e.g. http://localhost:4000")
    ap.add_argument("--admin-email", default=None)
    ap.add_argument("--admin-password", default=None)
    ap.add_argument("--customer-email", default=None)
    ap.add_argument("--customer-password", default=None)
    ap.add_argument("--out", default="fuzz_report.json", help="Output report JSON")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--max-cases-per-endpoint", type=int, default=120)
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    base_url = args.base_url or cfg.get("base_url")
    if not base_url:
        raise SystemExit("No base_url. Provide --base-url or set it in config.")

    # ---- Auth setup
    admin_email = args.admin_email or cfg["defaults"]["admin_email"]
    admin_password = args.admin_password or cfg["defaults"]["admin_password"]

    # Customer: if not provided, auto-register a random one
    customer_email = args.customer_email or f"user_{rands(8)}@sportshop.test"
    customer_password = args.customer_password or f"UserPass{rands(6)}!"

    # Register customer (idempotent-ish) then login both
    auth_cfg = cfg["auth"]
    auth_register(base_url, auth_cfg["register_path"], customer_email, customer_password)

    customer_token = auth_login(base_url, auth_cfg["login_path"], customer_email, customer_password, auth_cfg["token_field"])
    admin_token = auth_login(base_url, auth_cfg["login_path"], admin_email, admin_password, auth_cfg["token_field"])

    customer_headers = {"Content-Type": "application/json", **make_auth_header(cfg, customer_token)}
    admin_headers = {"Content-Type": "application/json", **make_auth_header(cfg, admin_token)}
    public_headers = {"Content-Type": "application/json"}

    # ---- Create baseline fixtures (product + order) so /{id} endpoints work
    # Create a product as admin (valid)
    product_payload = {
        "name": "Baseline Product " + rands(6),
        "description": "Baseline desc",
        "category": "Running",
        "priceCents": 1234,
        "stock": 50,
        "imageUrl": "https://example.com/base.png",
    }
    p_resp = requests.post(join_url(base_url, "/api/products"), json=product_payload, headers=admin_headers, timeout=args.timeout)
    if p_resp.status_code not in (200, 201):
        raise SystemExit(f"Could not create baseline product (need admin auth). Status={p_resp.status_code} Body={p_resp.text}")
    product_id = p_resp.json().get("id")

    # Create an order as customer
    order_payload = {"items": [{"productId": product_id, "quantity": 1}]}
    o_resp = requests.post(join_url(base_url, "/api/orders"), json=order_payload, headers=customer_headers, timeout=args.timeout)
    if o_resp.status_code not in (200, 201):
        raise SystemExit(f"Could not create baseline order. Status={o_resp.status_code} Body={o_resp.text}")
    order_id = o_resp.json().get("id")

    baseline_values = {
        "product_id": product_id,
        "order_id": order_id,
        "email": customer_email,
        "password": customer_password,
        "new_email": f"new_{rands(8)}@sportshop.test",
        "new_password": f"NewPass{rands(6)}!",
    }

    results: List[CaseResult] = []
    interesting: List[CaseResult] = []

    for ep in cfg["endpoints"]:
        ep_name = ep["name"]
        method = ep["method"].upper()
        auth = ep.get("auth", "none")

        # Choose headers
        if auth == "admin":
            headers = admin_headers
        elif auth == "customer":
            headers = customer_headers
        else:
            headers = public_headers

        # Build baseline request parts with placeholders resolved
        path_params = substitute_placeholders(ep.get("path_params") or {}, baseline_values)
        query = substitute_placeholders(ep.get("query") or {}, baseline_values)
        body_template = substitute_placeholders(ep.get("json"), baseline_values) if ep.get("json") is not None else None

        cases = build_cases_for_endpoint(ep, baseline_values)[: args.max_cases_per_endpoint]

        for case_name, mutation, sent_invalid in cases:
            # Apply mutations
            m_path = dict(path_params)
            if "path_params" in mutation:
                m_path.update(mutation["path_params"])

            # Render path with path params
            path = ep["path"]
            for k, v in m_path.items():
                path = path.replace("{" + k + "}", str(v))

            url = join_url(base_url, path)

            m_query = dict(query)
            if "query" in mutation:
                m_query.update(mutation["query"])

            json_body = apply_mutation_to_body(body_template if isinstance(body_template, dict) else body_template, mutation)

            # Fire request
            resp, err, elapsed_ms = http_request(method, url, headers, m_query, json_body, args.timeout)
            status = resp.status_code if resp is not None else None
            snippet = safe_snippet(resp.text if resp is not None else err or "")

            is_interesting, reason = mark_interesting(resp, err, elapsed_ms, sent_invalid)

            rr = CaseResult(
                endpoint=ep_name,
                method=method,
                url=url,
                status=status,
                elapsed_ms=elapsed_ms,
                request={
                    "case": case_name,
                    "headers": {k: ("<redacted>" if k.lower() == "authorization" else v) for k, v in headers.items()},
                    "params": m_query,
                    "json": json_body,
                },
                response_snippet=snippet,
                error=err,
                interesting=is_interesting,
                reason=reason,
            )
            results.append(rr)
            if is_interesting:
                interesting.append(rr)

    report = {
        "service": cfg.get("service_name"),
        "base_url": base_url,
        "created_fixtures": {"product_id": product_id, "order_id": order_id},
        "counts": {
            "total_cases": len(results),
            "interesting_cases": len(interesting),
        },
        "interesting": [asdict(x) for x in interesting],
        "runs": [asdict(x) for x in results],
    }

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Console summary
    print(f"Done. total_cases={len(results)} interesting_cases={len(interesting)} out={args.out}")
    # top 10 interesting
    for x in interesting[:10]:
        print(f"- [{x.endpoint}] {x.request['case']} -> status={x.status} reason={x.reason} url={x.url}")

if __name__ == "__main__":
    main()
