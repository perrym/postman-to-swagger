########################################################
# APISCAN - POSTMAN to SWAGGER converter GUI           #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.0 24-06-2026                               #
########################################################

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from tkinter import (
    Tk, Frame, Label, Entry, Button, Checkbutton, Radiobutton,
    StringVar, BooleanVar, Text, Scrollbar, filedialog, messagebox,
    DISABLED, NORMAL, END, WORD,
)
from tkinter.ttk import Progressbar, Style

# ── Import the converter ──────────────────────────────────────────────
import importlib.util

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("postman_to_swagger", _HERE / "postman-to-swagger.py")
_p2s = importlib.util.module_from_spec(_spec)
sys.modules["postman_to_swagger"] = _p2s
_spec.loader.exec_module(_p2s)

# ═══════════════════════════════════════════════════════════════════════
# GUI Application
# ═══════════════════════════════════════════════════════════════════════

PAD_X = 12
PAD_Y = 6
ENTRY_W = 55

TITLE_FONT = ("Segoe UI", 12, "bold")
HEADER_BG = "#0078d4"


class SwaggerGUI:
    def __init__(self, root: Tk) -> None:
        self.root = root
        root.title("Postman → Swagger Converter — by Perry Mertens")
        root.geometry("800x700")
        root.minsize(700, 560)
        root.resizable(True, True)

        # Dark-ish style
        style = Style(root)
        style.theme_use("clam")

        # ── Header ────────────────────────────────────────────────────
        header = Frame(root, bg=HEADER_BG, height=44)
        header.pack(fill="x")
        Label(header, text="  Postman → Swagger Converter", font=TITLE_FONT,
              bg=HEADER_BG, fg="white").pack(side="left", padx=PAD_X, pady=8)
        Label(header, text="by Perry Mertens pamsniffer@gmail.com (C)2026 License AGPL-v3.0  ", font=("Segoe UI", 8),
              bg=HEADER_BG, fg="#b0d4f1").pack(side="right", padx=PAD_X, pady=10)

        # ── Content area ──────────────────────────────────────────────
        content = Frame(root)
        content.pack(fill="both", expand=True, padx=PAD_X, pady=PAD_X)

        # Input files
        row = self._row(content, "Postman Collection *", self._mk_entry(content), "Browse...",
                         lambda: self._pick_json("Select Postman Collection"))
        self.coll_path = row["var"]
        self._row_gap(content)

        row = self._row(content, "Environment (optional)", self._mk_entry(content), "Browse...",
                         lambda: self._pick_json("Select Environment File"))
        self.env_path = row["var"]
        self._row_gap(content)

        row = self._row(content, "Output file", self._mk_entry(content, "openapi"), "Browse...",
                         self._browse_output)
        self.output_path = row["var"]
        self._row_gap(content)

        # Format
        fmt_frame = Frame(content)
        fmt_frame.pack(fill="x", pady=(2, 0))
        Label(fmt_frame, text="Format:").pack(side="left")
        self.fmt_var = StringVar(value="json")
        Radiobutton(fmt_frame, text="JSON only", variable=self.fmt_var, value="json").pack(side="left", padx=8)
        Radiobutton(fmt_frame, text="YAML only", variable=self.fmt_var, value="yaml").pack(side="left", padx=8)
        Radiobutton(fmt_frame, text="Both", variable=self.fmt_var, value="both").pack(side="left", padx=8)

        # Options row
        opt_frame = Frame(content)
        opt_frame.pack(fill="x", pady=(PAD_Y, 0))
        self.strict_var = BooleanVar(value=False)
        Checkbutton(opt_frame, text="Strict mode (fail on unresolved {{var}})", variable=self.strict_var).pack(
            side="left")

        Label(opt_frame, text="    Folder filter:").pack(side="left")
        self.folder_var = StringVar()
        Entry(opt_frame, textvariable=self.folder_var, width=16).pack(side="left", padx=4)
        Label(opt_frame, text="(optional)", foreground="gray").pack(side="left")

        Label(opt_frame, text="    Base URL:").pack(side="left", padx=(12, 0))
        self.base_url_var = StringVar()
        Entry(opt_frame, textvariable=self.base_url_var, width=22).pack(side="left", padx=4)

        # ── Buttons ───────────────────────────────────────────────────
        btn_frame = Frame(content)
        btn_frame.pack(fill="x", pady=(PAD_Y + 6, PAD_Y))

        self.convert_btn = Button(btn_frame, text="▶  Convert", command=self._convert,
                                   bg="#0078d4", fg="white", font=("Segoe UI", 10, "bold"),
                                   padx=24, pady=6, cursor="hand2")
        self.convert_btn.pack(side="left")

        self.preview_btn = Button(btn_frame, text="🌐  Preview in Swagger UI", command=self._preview,
                                   state=DISABLED, padx=14, pady=6)
        self.preview_btn.pack(side="left", padx=10)

        self.open_btn = Button(btn_frame, text="📂  Open Output Folder", command=self._open_folder,
                                state=DISABLED, padx=14, pady=6)
        self.open_btn.pack(side="left")

        # Progress bar (hidden initially)
        self.progress = Progressbar(content, mode="indeterminate")

        # ── Output log ────────────────────────────────────────────────
        log_frame = Frame(content)
        log_frame.pack(fill="both", expand=True, pady=(PAD_Y, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log = Text(log_frame, wrap=WORD, font=("Consolas", 9),
                         bg="#1e1e1e", fg="#d4d4d4", insertbackground="white",
                         relief="flat", borderwidth=6, state=NORMAL)
        self.log.grid(row=0, column=0, sticky="nsew")

        scroll = Scrollbar(log_frame, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        # Log color tags
        self.log.tag_config("ok", foreground="#6a9955")
        self.log.tag_config("warn", foreground="#ce9178")
        self.log.tag_config("err", foreground="#f44747")
        self.log.tag_config("info", foreground="#569cd6")
        self.log.tag_config("bold", foreground="#4ec9b0")
        self.log.tag_config("dim", foreground="#808080")

        # ── Status bar ────────────────────────────────────────────────
        self.status_var = StringVar(value="Ready — select a Postman collection and click Convert.")
        status_bar = Label(root, textvariable=self.status_var, relief="sunken", anchor="w",
                            font=("Segoe UI", 8), padx=8, pady=3)
        status_bar.pack(fill="x", side="bottom")

        self._log("Postman → Swagger Converter ready.", "dim")

    # ── Helpers ────────────────────────────────────────────────────────

    def _mk_entry(self, parent: Frame, default: str = "") -> StringVar:
        return StringVar(value=default)

    def _row(self, parent: Frame, label: str, var: StringVar, btn_text: str,
             btn_cmd) -> dict:
        f = Frame(parent)
        f.pack(fill="x")
        Label(f, text=label, width=22, anchor="w").pack(side="left")
        Entry(f, textvariable=var, width=ENTRY_W).pack(side="left", padx=4)
        Button(f, text=btn_text, command=btn_cmd, padx=8).pack(side="left")
        return {"var": var, "frame": f}

    def _row_gap(self, parent: Frame) -> None:
        Frame(parent, height=4).pack(fill="x")

    def _pick_json(self, title: str) -> None:
        path = filedialog.askopenfilename(
            title=title,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=str(_HERE),
        )
        if path:
            if "Collection" in title:
                self.coll_path.set(path)
            else:
                self.env_path.set(path)

    def _browse_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Output file (without extension)",
            defaultextension="",
            initialdir=str(_HERE),
            initialfile="openapi",
        )
        if path:
            self.output_path.set(str(Path(path).with_suffix("")))

    # ── Logging ────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "") -> None:
        self.log.insert(END, msg + "\n", tag)
        self.log.see(END)

    def _clear_log(self) -> None:
        self.log.delete("1.0", END)

    # ── Conversion ─────────────────────────────────────────────────────

    def _convert(self) -> None:
        coll_path = self.coll_path.get().strip()
        if not coll_path:
            messagebox.showwarning("Missing input", "Please select a Postman collection file.")
            return
        if not Path(coll_path).is_file():
            messagebox.showerror("File not found", f"Collection not found:\n{coll_path}")
            return

        self._clear_log()
        self._log("═" * 56, "info")
        self._log("  Postman → Swagger Converter", "bold")
        self._log("═" * 56, "info")
        self._log(f"  Collection : {Path(coll_path).name}", "dim")
        env_path = self.env_path.get().strip()
        self._log(f"  Environment: {Path(env_path).name if env_path else '(none)'}", "dim")
        self._log(f"  Output     : {Path(self.output_path.get().strip()).name}", "dim")
        self._log(f"  Format     : {self.fmt_var.get()}", "dim")
        self._log("")

        self.convert_btn.configure(state=DISABLED, text="⏳  Converting...")
        self.preview_btn.configure(state=DISABLED)
        self.open_btn.configure(state=DISABLED)
        self.progress.pack(fill="x", pady=(0, 4))
        self.progress.start()
        self.status_var.set("Converting...")

        threading.Thread(target=self._run_conversion, daemon=True).start()

    def _run_conversion(self) -> None:
        try:
            # Load collection
            coll = _p2s.load_json(self.coll_path.get().strip())
            self.root.after(0, lambda: self._log("  ✓ Collection loaded", "ok"))

            # Load env
            env = None
            env_path = self.env_path.get().strip()
            if env_path and Path(env_path).is_file():
                env = _p2s.load_json(env_path)
                self.root.after(0, lambda: self._log("  ✓ Environment loaded", "ok"))

            # Build context
            ctx = _p2s.VarContext(
                _p2s.vars_from_collection(coll),
                _p2s.vars_from_env(env),
                {},
            )
            merged = ctx.merged()
            self.root.after(0, lambda: self._log(f"  ✓ Variables resolved: {len(merged)}", "ok"))

            # Parse requests
            folder_filter = self.folder_var.get().strip() or None
            rows = _p2s.collect_requests(coll, ctx, folder_filter=folder_filter)
            if not rows:
                self.root.after(0, self._conversion_done, False, "No requests found (check folder filter).")
                return
            self.root.after(0, lambda: self._log(f"  ✓ Requests parsed: {len(rows)}", "ok"))

            # Detect / override base URL
            base_url = self.base_url_var.get().strip() or _p2s.detect_base_url(rows)
            self.root.after(0, lambda: self._log(f"  ✓ Base URL: {base_url}", "ok"))

            # Build spec
            spec = _p2s.build_spec(rows, base_url.rstrip("/"), strict=self.strict_var.get())
            paths = spec.get("paths", {})
            ops = sum(len(m) for m in paths.values())
            self.root.after(0, lambda: self._log(
                f"  ✓ Spec built: {len(paths)} paths, {ops} operations", "ok"))

            # Security info
            if "components" in spec and "securitySchemes" in spec["components"]:
                schemes = list(spec["components"]["securitySchemes"].keys())
                self.root.after(0, lambda: self._log(f"  ✓ Security: {', '.join(schemes)}", "ok"))

            # Write output
            out_base = Path(self.output_path.get().strip())
            fmt = self.fmt_var.get()
            write_json = fmt in ("json", "both")
            write_yaml = fmt in ("yaml", "both")

            files_written = []
            if write_json:
                out_json = out_base.with_suffix(".json")
                out_json.parent.mkdir(parents=True, exist_ok=True)
                with out_json.open("w", encoding="utf-8") as f:
                    json.dump(spec, f, indent=2, ensure_ascii=False)
                files_written.append(out_json.name)
                self.root.after(0, lambda n=out_json.name: self._log(f"  ✓ JSON: {n}", "ok"))

            if write_yaml:
                try:
                    import yaml
                    out_yaml = out_base.with_suffix(".yaml")
                    out_yaml.parent.mkdir(parents=True, exist_ok=True)
                    with out_yaml.open("w", encoding="utf-8") as f:
                        yaml.safe_dump(spec, f, sort_keys=False, allow_unicode=True)
                    files_written.append(out_yaml.name)
                    self.root.after(0, lambda n=out_yaml.name: self._log(f"  ✓ YAML: {n}", "ok"))
                except ImportError:
                    self.root.after(0, lambda: self._log(
                        "  ⚠ PyYAML not installed — run: pip install pyyaml", "warn"))

            self._last_spec_path = str(out_base.with_suffix(".json"))
            self._last_output_dir = str(out_base.parent)

            self.root.after(0, lambda: self._log(""))
            self.root.after(0, lambda: self._log("  ✅ Done!", "ok"))
            self.root.after(0, lambda: self._log(f"  Files: {', '.join(files_written)}", "dim"))
            self.root.after(0, self._conversion_done, True, "")
        except Exception as e:
            self.root.after(0, lambda msg=str(e): self._log(f"  ❌ Error: {msg}", "err"))
            self.root.after(0, self._conversion_done, False, str(e))

    def _conversion_done(self, success: bool, msg: str) -> None:
        self.progress.stop()
        self.progress.pack_forget()
        self.convert_btn.configure(state=NORMAL, text="▶  Convert")
        if success:
            self.preview_btn.configure(state=NORMAL)
            self.open_btn.configure(state=NORMAL)
            self.status_var.set("Conversion complete! Click Preview to open Swagger UI.")
        else:
            self.status_var.set(f"Failed: {msg}")

    # ── Preview ────────────────────────────────────────────────────────

    def _preview(self) -> None:
        spec_file = Path(self._last_spec_path)
        if not spec_file.is_file():
            messagebox.showerror("Missing spec", f"Spec file not found:\n{spec_file}")
            return

        # Write Swagger UI preview page into the output directory
        output_dir = spec_file.parent
        self._write_preview_page(output_dir)

        # Find free port
        port = 8000
        for p in range(8000, 8020):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", p))
                    port = p
                    break
            except OSError:
                continue

        self._log(f"\n  🌐 Starting server on http://127.0.0.1:{port} ...", "info")

        server_dir = str(output_dir)

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=server_dir, **kwargs)

            def log_message(self, fmt, *args):
                pass

        def run():
            try:
                httpd = HTTPServer(("127.0.0.1", port), Handler)
                self._server = httpd
                httpd.serve_forever()
            except Exception:
                pass

        threading.Thread(target=run, daemon=True).start()

        url = f"http://127.0.0.1:{port}/_preview.html?spec={spec_file.name}"
        self._log(f"  Opening browser: {url}", "dim")
        webbrowser.open(url)
        self.status_var.set(f"Preview running on port {port} — close app to stop server.")

    def _write_preview_page(self, output_dir: Path) -> None:
        """Write a Swagger UI preview page into the output directory."""
        html = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Swagger UI — Preview</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; }
    .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js" crossorigin="anonymous"></script>
  <script>
    window.onload = function() {
      var params = new URLSearchParams(window.location.search);
      var spec = params.get('spec') || 'openapi.json';
      SwaggerUIBundle({
        url: spec,
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        plugins: [SwaggerUIBundle.plugins.DownloadUrl],
        layout: "StandaloneLayout",
        defaultModelsExpandDepth: -1,
        docExpansion: "list"
      });
    };
  </script>
</body>
</html>"""
        (output_dir / "_preview.html").write_text(html, encoding="utf-8")

    def _open_folder(self) -> None:
        os.startfile(self._last_output_dir)


# ═══════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    root = Tk()

    # Try setting icon if available
    try:
        root.iconbitmap(default="")
    except Exception:
        pass

    app = SwaggerGUI(root)

    # Pre-load from CLI args
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--postman")
    ap.add_argument("--env")
    args, _ = ap.parse_known_args()
    if args.postman:
        app.coll_path.set(args.postman)
    if args.env:
        app.env_path.set(args.env)

    root.mainloop()


if __name__ == "__main__":
    main()
