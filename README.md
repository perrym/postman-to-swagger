# Postman → OpenAPI (Swagger) Converter
# part of APISCAN  OWASP API Security Scanner by Perry Mertens pamsniffer@gmail.com 2025 (c)
<meta content="VvYq2k5BFp5dpIL6JpQhoe90sWEXZTEBbaynlEKCWRE" name="google-site-verification">

This tool converts a **Postman v2.1 collection** into an **OpenAPI 3.0** specification (JSON and/or YAML).  
Author: **Perry Mertens** — MIT License.

## Features
- Variable resolution: `collection` → `environment` → `--var key=value`
- Server URL & server variables (or force with `--base-url`)
- `--strict`: fail on unresolved `{{var}}` in URL/path
- Path normalization: `/:id`, `{{var}}` → `{id}`; removes duplicate slashes
- Query merge: parameters from URL and Postman fields (deduplicated)
- Security detection: Bearer, Basic, `x-api-key` → `components.securitySchemes` + global `security`
- Relaxed JSON parsing for examples (removes comments and trailing commas)
- Response examples: builds minimal schemas from Postman `response` blocks
- Header parameter filtering (keeps `Authorization` and `Content-Type` out of generic params)
- JSON/YAML output; optional spec validation

## Requirements
- Python **3.9+**
- Optional (YAML output): `pip install pyyaml`
- Optional (validation): `pip install openapi-spec-validator`

## Usage
### Basic (JSON)
```bash
python postman-to-swagger.py   --postman ./MyCollection.postman_collection.json   --output ./out/openapi   --json-only
```

### With environment and variables (recommended)
```bash
python postman-to-swagger.py   --postman ./MyCollection.postman_collection.json   --env ./MyEnv.postman_environment.json   --var baseUrl=https://api.example.com   --output ./out/openapi   --json-only --strict
```

### YAML + JSON and base-url override
```bash
python postman-to-swagger.py   --postman ./MyCollection.json   --output ./out/openapi   --both --base-url https://api.example.com
```

## CLI Flags
| Flag | Description |
|------|-------------|
| `--postman <path>` | **Required.** Postman collection (v2.1) JSON. |
| `--env <path>` | Optional. Postman environment JSON; *enabled* keys feed `servers[0].variables`. |
| `--var key=value` | Optional, repeatable. CLI overrides for variables. |
| `--base-url <url>` | Force server URL; overrides auto-detection. |
| `--folder <name>` | Only include items whose folder name contains this substring. |
| `--json-only` / `--yaml-only` / `--both` | Output formats. |
| `--strict` | Fail if `{{var}}` remains in URLs/paths. |
| `--log-level [DEBUG|INFO|WARNING|ERROR]` | Logging level. |

## Workflows
1. **Per-module exports** (e.g., Policy/Claim): export by Postman subfolder or use `--folder` and different `--output` names.
2. **Scan with apiscan**: convert to OpenAPI first, then run your scanner:
   ```bash
   python apiscan.py --url https://api.example.com --swagger ./out/openapi.json --verify-plan --threads 8 --timeout 20
   ```

## Tips
- Multiple hosts in one collection? Run per subfolder or pass `--base-url`.
- If you want real request bodies/headers during scanning: adjust your scanner to use them (this converter provides schemas and examples).
- Postman rarely contains full models; generated schemas are indicative.

## Troubleshooting
- **“Invalid Postman structure”**: export as **Collection v2.1**, not an environment.  
- **Placeholders in server URL**: use `--env`, `--var`, or set `--base-url`.  
- **JSON parse errors in Postman**: remove comments/escape quotes. The converter is tolerant but not a magical fixer.  
- **Validation warnings**: install `openapi-spec-validator` to hard-validate.

---
© 2025 Perry Mertens — MIT License
