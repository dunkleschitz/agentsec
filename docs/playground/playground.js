/* agentsec in-browser playground. All scanning stays in this tab. */
(function () {
  "use strict";

  const PYODIDE_INDEX = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/";

  const TOOLS = {
    resultguard: {
      file: "resultguard.py",
      help: "Scans tool results in a saved transcript for indirect prompt injection. JSON transcripts work as-is; turn on “raw text” to scan a single pasted result.",
      rawFlag: "--as-result",
      extraArgs: ["--json", "--fail-on", "none"],
      ext: ".json",
      rawExt: ".txt",
      samples: [
        { id: "resultguard-poisoned.json", label: "Poisoned tool result (should flag)" },
        { id: "resultguard-clean.json", label: "Clean ticket transcript" },
      ],
    },
    secretflow: {
      file: "secretflow.py",
      help: "Flags a secret-shaped value that appears in a tool result and later in another tool’s arguments. Best with a JSON or JSONL transcript.",
      rawFlag: null,
      extraArgs: ["--json", "--fail-on", "none"],
      ext: ".json",
      rawExt: ".jsonl",
      samples: [
        { id: "secretflow-risky.json", label: "Secret reused in later tool args (should flag)" },
        { id: "secretflow-clean.json", label: "Public URL only, no secret flow" },
      ],
    },
    piiguard: {
      file: "piiguard.py",
      help: "Finds PII in transcripts or plain text and also writes a redacted copy, the same as piiguard --redact. Bundled samples use fictitious values only.",
      rawFlag: "--as-text",
      extraArgs: ["--json", "--fail-on", "none", "--redact", "/tmp/agentsec-redacted"],
      ext: ".json",
      rawExt: ".txt",
      samples: [
        { id: "piiguard-risky.txt", label: "Fictitious PII in plain text (should flag + redact)" },
        { id: "piiguard-clean.txt", label: "Plain follow-up with no PII" },
      ],
    },
    mcpposture: {
      file: "mcpposture.py",
      help: "Grades an MCP client config (Cursor, Claude Desktop, VS Code) for least-privilege and supply-chain issues. Paste a JSON config.",
      rawFlag: null,
      extraArgs: ["--json", "--no-color", "--exit-zero"],
      ext: ".json",
      rawExt: ".json",
      samples: [
        { id: "mcpposture-risky.json", label: "Broad, unpinned MCP config (should flag)" },
        { id: "mcpposture-clean.json", label: "Narrow, pinned MCP config" },
      ],
    },
    shellfence: {
      file: "shellfence.py",
      help: "Audits shell commands an agent ran. JSON transcripts work as-is; turn on “raw text” to scan one command per line.",
      rawFlag: "--as-commands",
      extraArgs: ["--json", "--fail-on", "none"],
      ext: ".json",
      rawExt: ".txt",
      samples: [
        { id: "shellfence-risky.json", label: "Dangerous shell commands (should flag)" },
        { id: "shellfence-clean.json", label: "Ordinary test commands" },
      ],
    },
  };

  const el = {
    tool: document.getElementById("tool"),
    sample: document.getElementById("sample"),
    input: document.getElementById("input"),
    asRaw: document.getElementById("as-raw"),
    run: document.getElementById("run"),
    status: document.getElementById("status"),
    help: document.getElementById("tool-help"),
    results: document.getElementById("results"),
  };

  let pyodide = null;
  let pyodideReady = false;
  const toolSource = {};

  function setStatus(text, kind) {
    el.status.textContent = text;
    el.status.className = "status" + (kind ? " " + kind : "");
  }

  function currentTool() {
    return TOOLS[el.tool.value] || TOOLS.resultguard;
  }

  function fillSamples() {
    const tool = currentTool();
    const prev = el.sample.value;
    el.sample.innerHTML = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = "— paste your own —";
    el.sample.appendChild(blank);
    for (const s of tool.samples) {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = s.label;
      el.sample.appendChild(opt);
    }
    if ([...el.sample.options].some((o) => o.value === prev)) {
      el.sample.value = prev;
    }
    el.help.textContent = tool.help;
    const firstSample = tool.samples[0];
    const looksRaw = firstSample && /\.txt$/.test(firstSample.id);
    if (!el.input.value.trim()) {
      el.asRaw.checked = !!looksRaw;
    }
  }

  async function loadSample(id) {
    if (!id) return;
    const res = await fetch("samples/" + encodeURIComponent(id));
    if (!res.ok) {
      throw new Error("Could not load sample " + id + " (" + res.status + ")");
    }
    el.input.value = await res.text();
    el.asRaw.checked = /\.txt$/.test(id);
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function findingsOf(obj) {
    if (!obj || typeof obj !== "object") return [];
    if (Array.isArray(obj.findings)) return obj.findings;
    if (Array.isArray(obj)) return obj;
    return [];
  }

  function findingRule(f) {
    return f.rule || f.rule_id || f.id || "";
  }

  function findingSeverity(f) {
    return (f.severity || "info").toLowerCase();
  }

  function renderResults(payload, redacted, argv) {
    const findings = findingsOf(payload);
    const counts = {};
    for (const f of findings) {
      const sev = findingSeverity(f);
      counts[sev] = (counts[sev] || 0) + 1;
    }
    const parts = [];
    parts.push(
      '<p class="summary-line" id="scan-summary">' +
        findings.length +
        " finding" +
        (findings.length === 1 ? "" : "s") +
        (Object.keys(counts).length
          ? " · " +
            Object.keys(counts)
              .map((k) => counts[k] + " " + k)
              .join(", ")
          : " · clean at the configured threshold") +
        "</p>"
    );
    if (!findings.length) {
      parts.push('<p class="results-empty">No findings at or above the tool’s default reporting floor.</p>');
    }
    for (const f of findings) {
      const sev = findingSeverity(f);
      const rule = findingRule(f);
      const title = f.title || f.message || rule || "finding";
      const excerpt = f.excerpt || f.snippet || f.match || f.detail || f.message || "";
      const meta = [rule, sev, f.tool, f.source].filter(Boolean).join(" · ");
      parts.push(
        '<article class="finding sev-' +
          escapeHtml(sev) +
          '">' +
          (meta ? '<p class="meta">' + escapeHtml(meta) + "</p>" : "") +
          '<p class="title">' +
          escapeHtml(title) +
          "</p>" +
          (excerpt && excerpt !== title
            ? '<p class="excerpt">' + escapeHtml(String(excerpt)) + "</p>"
            : "") +
          "</article>"
      );
    }
    if (typeof redacted === "string" && redacted.length) {
      parts.push(
        "<h3>Redacted copy</h3><div class=\"redacted\"><pre>" +
          escapeHtml(redacted) +
          "</pre></div>"
      );
    }
    parts.push(
      "<details class=\"raw-json\"><summary>Raw JSON and command</summary><pre>" +
        escapeHtml((argv || []).join(" ") + "\n\n" + JSON.stringify(payload, null, 2)) +
        "</pre></details>"
    );
    el.results.innerHTML = parts.join("\n");
  }

  function guessExt(tool, text, asRaw) {
    if (asRaw) return tool.rawExt || ".txt";
    const trimmed = text.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) return ".json";
    if (/^[^\n]*\{/.test(trimmed) && trimmed.includes("\n")) return ".jsonl";
    return tool.ext || ".txt";
  }

  async function ensurePyodide() {
    if (pyodideReady) return pyodide;
    setStatus("Loading the Python runtime from the Pyodide CDN…");
    pyodide = await loadPyodide({ indexURL: PYODIDE_INDEX });
    pyodide.FS.mkdirTree("/opt/agentsec");
    pyodide.FS.mkdirTree("/tmp");
    for (const [name, cfg] of Object.entries(TOOLS)) {
      const res = await fetch("vendor/" + cfg.file);
      if (!res.ok) {
        throw new Error("Could not load " + cfg.file + " (" + res.status + ")");
      }
      toolSource[name] = await res.text();
      pyodide.FS.writeFile("/opt/agentsec/" + cfg.file, toolSource[name]);
    }
    pyodideReady = true;
    setStatus("Python runtime ready. Scanning stays in this browser.", "ready");
    return pyodide;
  }

  async function runScan() {
    const name = el.tool.value;
    const tool = TOOLS[name];
    const text = el.input.value;
    if (!text.trim()) {
      setStatus("Paste some input, or load a sample fixture.", "error");
      return;
    }
    el.run.disabled = true;
    try {
      await ensurePyodide();
      setStatus("Scanning in this browser…");
      const asRaw = el.asRaw.checked;
      const ext = guessExt(tool, text, asRaw);
      const inPath = "/tmp/agentsec-input" + ext;
      const redactPath = "/tmp/agentsec-redacted";
      try {
        pyodide.FS.unlink(redactPath);
      } catch (e) {
        /* missing is fine */
      }
      pyodide.FS.writeFile(inPath, text);
      const argv = [name].concat(tool.extraArgs);
      if (asRaw && tool.rawFlag) argv.push(tool.rawFlag);
      argv.push(inPath);

      pyodide.globals.set("AGENTSEC_ARGV", pyodide.toPy(argv));
      pyodide.globals.set("AGENTSEC_SCRIPT", "/opt/agentsec/" + tool.file);

      const py = `
import io, runpy, sys
_out, _err = io.StringIO(), io.StringIO()
_argv = list(AGENTSEC_ARGV)
_old_out, _old_err, _old_argv = sys.stdout, sys.stderr, sys.argv
sys.stdout, sys.stderr, sys.argv = _out, _err, _argv
_code = 0
try:
    runpy.run_path(AGENTSEC_SCRIPT, run_name="__main__")
except SystemExit as _e:
    try:
        _code = int(_e.code or 0)
    except (TypeError, ValueError):
        _code = 1
finally:
    sys.stdout, sys.stderr, sys.argv = _old_out, _old_err, _old_argv
{"stdout": _out.getvalue(), "stderr": _err.getvalue(), "code": _code}
`;
      const result = pyodide.runPython(py).toJs({ dict_converter: Object.fromEntries });
      const stdout = result.stdout || "";
      const stderr = result.stderr || "";
      let payload;
      try {
        payload = JSON.parse(stdout);
      } catch (e) {
        throw new Error(
          "The tool did not emit JSON.\n" +
            (stdout || stderr || "(no output)") +
            (stderr && stdout ? "\n\nstderr:\n" + stderr : "")
        );
      }
      let redacted = "";
      if (name === "piiguard") {
        try {
          redacted = pyodide.FS.readFile(redactPath, { encoding: "utf8" });
        } catch (e) {
          redacted = "";
        }
      }
      renderResults(payload, redacted, argv);
      const n = findingsOf(payload).length;
      setStatus(
        "Done. " + n + " finding" + (n === 1 ? "" : "s") + " — nothing was uploaded.",
        "ready"
      );
    } catch (err) {
      setStatus(String(err && err.message ? err.message : err), "error");
    } finally {
      el.run.disabled = false;
    }
  }

  el.tool.addEventListener("change", function () {
    fillSamples();
  });
  el.sample.addEventListener("change", function () {
    if (!el.sample.value) return;
    loadSample(el.sample.value).catch(function (err) {
      setStatus(String(err && err.message ? err.message : err), "error");
    });
  });
  el.run.addEventListener("click", runScan);

  fillSamples();
  el.run.disabled = true;
  ensurePyodide()
    .then(function () {
      el.run.disabled = false;
    })
    .catch(function (err) {
      setStatus(
        "Could not load the Python runtime. Check your network (Pyodide is fetched from jsDelivr) and reload. " +
          (err && err.message ? err.message : err),
        "error"
      );
      el.run.disabled = false;
    });
})();
