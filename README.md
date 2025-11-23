# Postman to Swagger Converter by Perry Mertens pamsniffer@gmail.com license  AGPL-3.0  (C)2025

This project converts a Postman v2.1 collection to an OpenAPI 3.0 spec and serves it with a lightweight web preview.


## 1) Requirements
- Python 3.9+
- Optional (for YAML output): `pip install pyyaml`

## 2) Convert your Postman collection
```bash
python postman-to-swagger.py   --postman Collection.postman_collection.json   --env postmanenvironment.json   --output test   --json-only
```
Outputs: `test.json` (and `test.yaml` if you omit `--json-only` and have PyYAML).

**Environment usage:** any enabled key in `postmanenvironment.json` that matches a server variable (e.g. `token_host`) becomes the default in `servers[0].variables` of the spec.

## 3) Quick preview options
### A) Open the generated spec file
```bash
python postman-to-swagger.py --postman Collection.postman_collection.json --output test --open-ui
```
This opens the raw JSON in your default browser (no UI).

### B) Start a tiny web server and use Swagger UI
```bash
python postman-to-swagger.py   --postman Collection.postman_collection.json   --env postmanenvironment.json   --output test   --json-only   --serve
```
Then open:
```
http://localhost:8000/index.html?spec=test.json
```
> The built-in server serves the folder; it opens the spec file by default, but you can manually navigate to `index.html` for the Swagger UI.

Alternatively, you can use Python’s standard server:
```bash
python -m http.server 8000
# then browse to http://localhost:8000/index.html?spec=test.json
```

## 4) Tips
- Use `--yaml-only` or `--json-only` to control output format (default is both if neither is passed).
- The converter normalizes paths (`{{var}}` → `{var}`), pulls request/response bodies into components, and de-duplicates parameters.

## 5) Troubleshooting
- **`Invalid Postman structure`**: ensure you exported a **collection v2.1**, not an environment.
- **No server defaults**: pass `--env postmanenvironment.json` and confirm the keys are enabled.
- **Want multiple modules**: run the converter per subfolder and choose different `--output` names (e.g., `policy.json`, `claim.json`).

