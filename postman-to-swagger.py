#######################################################
# APISCAN - POSTMAN to SWAGGER converter              #
# Licensed under the MIT License                      #
# Author: Perry Mertens pamsniffer@gmail.com (c) 2025 #
#######################################################
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlparse, parse_qsl

# =====================================================
# Postman → OpenAPI 3.0 converter (all-in-one edition)
# - Variable resolution: collection → env → --var
# - Server variables and/or --base-url override
# - Strict mode for unresolved {{var}}
# - Path normalization (/:id, {{var}} → {id})
# - Query param merge (URL + Postman fields)
# - SecuritySchemes detection (bearer/basic/x-api-key)
# - Relaxed JSON parsing (strip comments; allow examples)
# - Responses with examples from Postman "response" blocks
# - Header parameter filtering (no Authorization/Content-Type)
# - Parameter dedupe (by name+in)
# - JSON and/or YAML output; optional validation
# =====================================================

JSONLike = Dict[str, Any]
PM_VAR = re.compile(r"{{\s*([A-Za-z0-9_.\-]+)\s*}}")

SENSITIVE_HEADERS = {"authorization", "content-type"}
HEADER_PARAM_DENYLIST = {"authorization"}  

def load_json(path: str | Path) -> JSONLike:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def strip_json_comments(s: str) -> str:
    s = re.sub(r"(?m)//.*?$", "", s)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return s

def relaxed_json_parse(s: str) -> Tuple[Optional[Any], Optional[str]]:
    """Try parsing JSON after removing comments and trivial trailing commas."""
    raw = s
    s = strip_json_comments(s)
    s = re.sub(r",\s*([}\]])", r"\1", s)
    try:
        return json.loads(s), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def is_unresolved(s: str) -> bool:
    return bool(PM_VAR.search(s or ""))

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")

@dataclass
class VarContext:
    coll: Dict[str, Any]
    env: Dict[str, Any]
    cli: Dict[str, Any]

    def merged(self) -> Dict[str, Any]:
        m: Dict[str, Any] = {}
        m.update(self.coll or {})
        m.update(self.env or {})
        m.update(self.cli or {})
        return m

    def resolve(self, s: str) -> str:
        if not isinstance(s, str):
            return s
        merged = self.merged()
        def repl(m: re.Match) -> str:
            key = m.group(1)
            val = merged.get(key)
            return str(val) if val is not None else m.group(0)
        return PM_VAR.sub(repl, s)

def vars_from_collection(coll: JSONLike) -> Dict[str, Any]:
    out = {}
    for v in (coll.get("variable") or []):
        k = v.get("key") or v.get("id")
        if k:
            out[str(k)] = v.get("value")
    return out

def vars_from_env(env: Optional[JSONLike]) -> Dict[str, Any]:
    out = {}
    if not env:
        return out
    for v in (env.get("values") or []):
        k = v.get("key")
        if k and not v.get("disabled"):
            out[str(k)] = v.get("value")
    return out

def normalize_path(raw_path: str) -> str:
    raw_path = raw_path or "/"
    # /:id → /{id}
    def repl(m: re.Match) -> str:
        return "/{%s}" % m.group(1)
    p = re.sub(r"/:([A-Za-z0-9_]+)", repl, raw_path)
    # {{var}} → {var}
    p = p.replace("{{", "{").replace("}}", "}")
    # collapse //
    p = re.sub(r"//+", "/", p)
    if not p.startswith("/"):
        p = "/" + p
    return p

def json_to_schema(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, dict):
        return {"type": "object", "properties": {k: json_to_schema(v) for k, v in obj.items()}}
    if isinstance(obj, list):
        return {"type": "array", "items": json_to_schema(obj[0]) if obj else {}}
    if isinstance(obj, bool):
        return {"type": "boolean"}
    if isinstance(obj, (int, float)):
        return {"type": "number"}
    return {"type": "string"}

def build_request_body(raw: Any) -> Optional[Dict[str, Any]]:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return {"content": {"application/json": {"schema": json_to_schema(raw), "example": raw}}}
    if isinstance(raw, str):
        data, err = relaxed_json_parse(raw)
        if err is None and data is not None:
            return {"content": {"application/json": {"schema": json_to_schema(data), "example": data}}}
        return {"content": {"text/plain": {"schema": {"type": "string"}, "example": raw}}}
    return None

def extract_query_params(url: str, pm_query_list: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    u = urlsplit(url or "")
    pairs = dict(parse_qsl(u.query, keep_blank_values=True))
    for q in (pm_query_list or []):
        if q.get("disabled"):
            continue
        k = q.get("key")
        v = q.get("value", "")
        if k:
            pairs.setdefault(k, v)
    out = []
    for k, v in pairs.items():
        out.append({
            "name": str(k),
            "in": "query",
            "required": False,
            "schema": {"type": "string"},
            **({"example": v} if v is not None else {})
        })
    return out

def extract_header_params(headers: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    params = []
    for h in headers or []:
        k = str(h.get("key",""))
        v = h.get("value")
        kl = k.lower()
        if not k or kl in HEADER_PARAM_DENYLIST:
            continue
        params.append({
            "name": k,
            "in": "header",
            "required": False,
            "schema": {"type": "string"},
            **({"example": v} if v is not None else {})
        })
    return params

def infer_security_from_headers(all_headers: List[Dict[str, str]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    schemes: Dict[str, Any] = {}
    security: List[Dict[str, Any]] = []
    low = [(h.get("key","").lower(), str(h.get("value","")).lower()) for h in (all_headers or [])]
    if any(k == "authorization" and "bearer" in v for k, v in low):
        schemes["bearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        security.append({"bearerAuth": []})
    if any(k == "authorization" and "basic" in v for k, v in low):
        schemes["basicAuth"] = {"type": "http", "scheme": "basic"}
        security.append({"basicAuth": []})
    if any(k in {"x-api-key", "apikey", "api-key"} for k, v in low):
        schemes["apiKeyHeader"] = {"type": "apiKey", "in": "header", "name": "x-api-key"}
        security.append({"apiKeyHeader": []})
    return schemes, security

def iter_items(items: List[JSONLike] | None):
    for it in items or []:
        if "item" in it:
            yield from iter_items(it["item"])
        elif "request" in it:
            yield it

def parse_request(it: JSONLike, ctx: VarContext) -> Dict[str, Any]:
    req = it.get("request", {})
    name = it.get("name") or req.get("name") or ""
    method = (req.get("method") or "GET").upper()

    # URL building
    raw_url = req.get("url")
    pm_query_list = None
    if isinstance(raw_url, str):
        url_raw = ctx.resolve(raw_url)
    elif isinstance(raw_url, dict):
        if "raw" in raw_url and isinstance(raw_url["raw"], str):
            url_raw = ctx.resolve(raw_url["raw"])
        else:
            protocol = raw_url.get("protocol", "https")
            host = raw_url.get("host")
            path = raw_url.get("path")
            port = raw_url.get("port")
            host_str = ".".join(host) if isinstance(host, list) else (host or "")
            path_str = "/".join(path) if isinstance(path, list) else (path or "")
            if port:
                host_str = f"{host_str}:{port}"
            url_raw = f"{protocol}://{host_str}/{path_str}".rstrip("/")
            url_raw = ctx.resolve(url_raw)
        pm_query_list = raw_url.get("query") if isinstance(raw_url, dict) else None
    else:
        url_raw = ""

    # Headers
    headers = []
    for h in (req.get("header") or []):
        if h.get("disabled"):
            continue
        key = ctx.resolve(h.get("key",""))
        val = ctx.resolve(h.get("value",""))
        if key:
            headers.append({"key": key, "value": val})

    # Auth → header mapping
    auth = req.get("auth")
    if isinstance(auth, dict) and "type" in auth:
        t = auth.get("type")
        a = auth.get(t) if t else None
        if isinstance(a, list):
            kv = {i.get("key"): i.get("value") for i in a if isinstance(i, dict)}
            if t == "bearer" and "token" in kv:
                headers.append({"key": "Authorization", "value": f"Bearer {ctx.resolve(kv['token'])}"})
            if t == "apikey" and {"key","value","in"} <= set(kv):
                if kv["in"] == "header":
                    headers.append({"key": ctx.resolve(kv["key"]), "value": ctx.resolve(kv["value"])})
            if t == "basic" and {"username","password"} <= set(kv):
                import base64
                token = base64.b64encode(f"{kv['username']}:{kv['password']}".encode()).decode()
                headers.append({"key":"Authorization","value":f"Basic {token}"})

    # Body
    body = req.get("body")
    body_mode = None
    body_payload: Any = None
    if isinstance(body, dict) and not body.get("disabled"):
        mode = body.get("mode")
        body_mode = mode
        if mode == "raw":
            raw = body.get("raw")
            if isinstance(raw, str):
                body_payload = ctx.resolve(raw)
        elif mode == "urlencoded":
            data = {}
            for p in body.get("urlencoded", []):
                if p.get("disabled"):
                    continue
                k = ctx.resolve(p.get("key",""))
                v = ctx.resolve(p.get("value",""))
                if k: data[k] = v
            body_payload = data
            body_mode = "form"
        elif mode == "formdata":
            data = {}
            for p in body.get("formdata", []):
                if p.get("disabled"):
                    continue
                k = ctx.resolve(p.get("key",""))
                v = ctx.resolve(p.get("value",""))
                if k: data[k] = v
            body_payload = data
            body_mode = "form"

    # Query params
    qparams = extract_query_params(url_raw, pm_query_list)

    # Responses from Postman (if present)
    oas_responses: Dict[str, Any] = {}
    for resp in it.get("response", []) or []:
        try:
            code = str(resp.get("code") or "200")
            desc = resp.get("status") or "OK"
            body_text = resp.get("body")
            if isinstance(body_text, str):
                data, err = relaxed_json_parse(body_text)
                if err is None and data is not None:
                    oas_responses[code] = {
                        "description": desc,
                        "content": {"application/json": {"schema": json_to_schema(data), "example": data}}
                    }
                else:
                    oas_responses[code] = {
                        "description": desc,
                        "content": {"text/plain": {"schema": {"type": "string"}, "example": body_text}}
                    }
            else:
                oas_responses[code] = {"description": desc}
        except Exception:
            pass

    return {
        "name": name,
        "method": method,
        "url": url_raw,
        "headers": headers,
        "qparams": qparams,
        "body": body_payload,
        "body_mode": body_mode,
        "tag": it.get("name") or "postman",
        "responses": oas_responses,
    }

def collect_requests(coll: JSONLike, ctx: VarContext, folder_filter: Optional[str]) -> List[Dict[str, Any]]:
    items = coll.get("item", [])
    if folder_filter:
        picked = []
        for it in items:
            if folder_filter.lower() in (it.get("name","").lower()):
                picked.append(it)
        items = picked or items
    out = []
    for it in iter_items(items):
        out.append(parse_request(it, ctx))
    return out

def detect_base_url(rows: List[Dict[str, Any]]) -> str:
    hosts = [f"{urlsplit(r['url']).scheme}://{urlsplit(r['url']).netloc}" for r in rows if r.get("url")]
    if not hosts:
        return "https://api.example.com"
    return Counter(hosts).most_common(1)[0][0]

def build_spec(rows: List[Dict[str, Any]], base_url: str, strict: bool) -> Dict[str, Any]:
    all_headers = []
    for r in rows:
        all_headers.extend(r.get("headers") or [])
    schemes, security = infer_security_from_headers(all_headers)

    paths: Dict[str, Any] = {}
    for r in rows:
        u = urlsplit(r["url"] or "")
        raw_path = u.path or "/"
        path = normalize_path(raw_path)
        method = r["method"].lower()

        if strict and (is_unresolved(r["url"]) or is_unresolved(path)):
            raise ValueError(f"Unresolved variable in URL/path: {r['url']}")
        params = []
        params.extend(r.get("qparams") or [])
        params.extend(extract_header_params(r.get("headers") or []))
        ded = {}
        for p in params:
            ded[(p["name"], p["in"])] = p
        params = list(ded.values())

        op = {
            "operationId": f"{slug(r.get('tag'))}_{method}_{slug(path)}",
            "tags": [r.get("tag") or "postman"],
            "parameters": params,
            "responses": r.get("responses") or {
                "200": {"description": "OK"},
                "401": {"description": "Unauthorized"},
                "403": {"description": "Forbidden"},
                "404": {"description": "Not Found"},
            },
        }
        rb = build_request_body(r.get("body"))
        if rb:
            op["requestBody"] = rb

        paths.setdefault(path, {})
        if method in paths[path]:
            prev = paths[path][method]
            prev["tags"] = sorted(set((prev.get("tags") or []) + (op.get("tags") or [])))
            pmap = {(p["name"], p["in"]): p for p in prev.get("parameters", [])}
            for p in op.get("parameters", []):
                pmap[(p["name"], p["in"])] = p
            prev["parameters"] = list(pmap.values())
           
            if "requestBody" not in prev and "requestBody" in op:
                prev["requestBody"] = op["requestBody"]
            
            for code, resp in (op.get("responses") or {}).items():
                prev.setdefault("responses", {}).setdefault(code, resp)
        else:
            paths[path][method] = op

    server_obj = {"url": base_url}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Converted from Postman", "version": "1.0.0"},
        "servers": [server_obj],
        "paths": paths,
    }
    if schemes:
        spec["components"] = {"securitySchemes": schemes}
    if security:
        spec["security"] = security
    return spec

# ---------------- CLI ----------------

def parse_cli_vars(kvs: Optional[List[str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for kv in kvs or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def main():
    ap = argparse.ArgumentParser(description="Convert Postman collection to OpenAPI 3.0 (all-in-one)")
    ap.add_argument("--postman", required=True, help="Path to Postman collection (v2.1)")
    ap.add_argument("--env", help="Path to Postman environment (optional)")
    ap.add_argument("--output", required=True, help="Output base path without extension")
    ap.add_argument("--json-only", action="store_true", help="Write only JSON")
    ap.add_argument("--yaml-only", action="store_true", help="Write only YAML")
    ap.add_argument("--both", action="store_true", help="Write both JSON and YAML")
    ap.add_argument("--folder", help="Only include folders containing this string (case-insensitive)")
    ap.add_argument("--base-url", help="Override base URL (otherwise majority host is used)")
    ap.add_argument("--var", action="append", help="Variable override key=value (repeatable)")
    ap.add_argument("--strict", action="store_true", help="Fail if unresolved {{var}} remain in URLs/paths")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")

    coll = load_json(args.postman)
    env = load_json(args.env) if args.env else None

    ctx = VarContext(vars_from_collection(coll), vars_from_env(env), parse_cli_vars(args.var))
    rows = collect_requests(coll, ctx, folder_filter=args.folder)
    if not rows:
        logging.error("No requests found in collection (after folder filter).")
        sys.exit(2)

    base_url = (args.base_url or detect_base_url(rows)).rstrip("/")
    spec = build_spec(rows, base_url, strict=args.strict)

    out_base = Path(args.output)
    write_json = args.json_only or args.both or (not args.yaml_only and not args.json_only and not args.both)
    write_yaml = args.yaml_only or args.both

    if write_json:
        out_json = out_base.with_suffix(".json")
        out_json.parent.mkdir(parents=True, exist_ok=True)
        with out_json.open("w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)
        logging.info("Wrote JSON: %s", str(out_json))

    if write_yaml:
        try:
            import yaml
            out_yaml = out_base.with_suffix(".yaml")
            out_yaml.parent.mkdir(parents=True, exist_ok=True)
            with out_yaml.open("w", encoding="utf-8") as f:
                yaml.safe_dump(spec, f, sort_keys=False, allow_unicode=True)
            logging.info("Wrote YAML: %s", str(out_yaml))
        except Exception:
            logging.error("PyYAML not installed; cannot write YAML.")

    # Optional: validate
    try:
        from openapi_spec_validator import validate_spec
        validate_spec(deepcopy(spec))
        logging.info("OpenAPI validation: OK")
    except Exception as e:
        logging.warning("OpenAPI validation skipped or warnings: %s", e)

if __name__ == "__main__":
    main()
