from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import shlex, re, os, time, subprocess, tempfile
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

app = FastAPI(title="SafeShell AI")

# Small transparent inbuilt NLP knowledge base.
# This is intentionally auditable for a hackathon prototype.
INTENT_EXAMPLES = {
    "READ": [
        "view files", "list files", "show files", "read a file",
        "inspect a directory", "check folder contents"
    ],
    "CREATE": [
        "create a file", "create a folder", "make a directory",
        "create a new file"
    ],
    "DELETE": [
        "delete files", "remove files", "clean old files",
        "remove temporary files"
    ],
    "COPY": ["copy a file", "duplicate a file", "make a copy"],
    "MOVE": ["move a file", "rename a file", "move files"],
    "PERMISSION_CHANGE": ["change file permissions", "make a file executable"],
    "PROCESS_CONTROL": ["stop a process", "terminate a process", "kill a process"],
    "NETWORK": ["download something", "connect to a server", "send data"],
    "SYSTEM_CONFIGURATION": ["change system configuration", "modify system settings"],
    "PACKAGE_CHANGE": ["install a package", "remove a package", "update software"],
}

all_text = []
all_labels = []
for label, examples in INTENT_EXAMPLES.items():
    all_text.extend(examples)
    all_labels.extend([label] * len(examples))

vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
matrix = vectorizer.fit_transform(all_text)

DANGEROUS_COMMANDS = {
    "rm": ("DELETE", 45),
    "rmdir": ("DELETE", 40),
    "chmod": ("PERMISSION_CHANGE", 35),
    "chown": ("PERMISSION_CHANGE", 40),
    "kill": ("PROCESS_CONTROL", 40),
    "pkill": ("PROCESS_CONTROL", 50),
    "killall": ("PROCESS_CONTROL", 55),
    "curl": ("NETWORK", 20),
    "wget": ("NETWORK", 25),
    "ssh": ("NETWORK", 20),
    "scp": ("NETWORK", 20),
    "apt": ("PACKAGE_CHANGE", 30),
    "apt-get": ("PACKAGE_CHANGE", 30),
    "dnf": ("PACKAGE_CHANGE", 30),
    "systemctl": ("SYSTEM_CONFIGURATION", 40),
}

SENSITIVE_PATHS = ["/", "/etc", "/boot", "/usr", "/var", "/home", "/root"]
SAFE_EXECUTABLES = {"pwd", "ls", "echo", "whoami", "id", "cat", "mkdir"}

class AnalyzeRequest(BaseModel):
    intent: str
    command: str

def extract_paths(tokens):
    paths = []
    for t in tokens:
        if t.startswith(("/", "~", "./", "../")) or "/" in t:
            paths.append(t.strip("'\""))
    return paths

def parse_command(command):
    try:
        tokens = shlex.split(command, posix=True)
        parse_error = None
    except ValueError as e:
        tokens = []
        parse_error = str(e)

    if not tokens:
        return {
            "valid": False, "error": parse_error or "Empty command",
            "command": "", "tokens": [], "paths": [], "privileged": False,
            "chaining": False, "redirect": False, "operation": "UNKNOWN"
        }

    base = tokens[0]
    privileged = base == "sudo" or "sudo" in tokens[:2]
    actual = tokens[1] if base == "sudo" and len(tokens) > 1 else base
    paths = extract_paths(tokens)
    chaining = any(x in command for x in ["&&", "||", ";", "|"])
    redirect = any(x in tokens for x in [">", ">>", "<"])

    operation = "UNKNOWN"
    if actual in {"ls", "cat", "pwd", "head", "tail", "find", "grep"}:
        operation = "READ"
    elif actual in {"mkdir", "touch"}:
        operation = "CREATE"
    elif actual in {"rm", "rmdir"}:
        operation = "DELETE"
    elif actual in {"cp"}:
        operation = "COPY"
    elif actual in {"mv"}:
        operation = "MOVE"
    elif actual in {"chmod", "chown"}:
        operation = "PERMISSION_CHANGE"
    elif actual in {"kill", "pkill", "killall"}:
        operation = "PROCESS_CONTROL"
    elif actual in {"curl", "wget", "ssh", "scp"}:
        operation = "NETWORK"
    elif actual in {"apt", "apt-get", "dnf", "yum", "pacman"}:
        operation = "PACKAGE_CHANGE"
    elif actual in {"systemctl"}:
        operation = "SYSTEM_CONFIGURATION"

    return {
        "valid": True, "error": None, "command": actual, "tokens": tokens,
        "paths": paths, "privileged": privileged, "chaining": chaining,
        "redirect": redirect, "operation": operation
    }

def infer_intent(text):
    vec = vectorizer.transform([text])
    scores = cosine_similarity(vec, matrix)[0]
    idx = int(scores.argmax())
    label = all_labels[idx]
    confidence = float(scores[idx])
    return label, round(confidence, 3)

def risk_analysis(parsed):
    score = 0
    factors = []
    cmd = parsed["command"]

    if cmd in DANGEROUS_COMMANDS:
        _, pts = DANGEROUS_COMMANDS[cmd]
        score += pts
        factors.append(f"{cmd}: potentially sensitive operation")

    if parsed["privileged"]:
        score += 30
        factors.append("elevated privilege requested")

    if parsed["chaining"]:
        score += 15
        factors.append("command chaining detected")

    if parsed["redirect"]:
        score += 10
        factors.append("output/input redirection detected")

    for p in parsed["paths"]:
        norm = os.path.expanduser(p)
        if norm in SENSITIVE_PATHS or norm.startswith(("/etc/", "/boot/", "/usr/", "/root/")):
            score += 30
            factors.append(f"sensitive target path: {p}")
        if p in {"/", "/*", "~"} or "*" in p:
            score += 25
            factors.append(f"broad target scope: {p}")

    if parsed["operation"] == "UNKNOWN":
        score += 25
        factors.append("unknown or unsupported operation")

    score = min(score, 100)
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level, factors

def intent_contract(user_intent, inferred, confidence):
    operation = inferred
    target = "UNSPECIFIED"
    m = re.search(r"(?:in|from|inside|under|at)\s+([~/.][^\s,]+)", user_intent, re.I)
    if m:
        target = m.group(1)
    constraints = {
        "network": inferred != "NETWORK",
        "modification": inferred not in {"DELETE", "CREATE", "COPY", "MOVE", "PERMISSION_CHANGE", "SYSTEM_CONFIGURATION", "PACKAGE_CHANGE"},
        "privilege": "NORMAL"
    }
    return {
        "goal": user_intent,
        "operation": operation,
        "target": target,
        "confidence": confidence,
        "constraints": constraints
    }

def alignment(contract, parsed):
    reasons = []
    score = 100
    if contract["operation"] != parsed["operation"]:
        score -= 45
        reasons.append(f"operation mismatch: intent={contract['operation']} command={parsed['operation']}")
    else:
        reasons.append("operation matches")

    if contract["target"] != "UNSPECIFIED":
        wanted = os.path.expanduser(contract["target"])
        if parsed["paths"]:
            actual = os.path.expanduser(parsed["paths"][-1])
            if wanted not in actual and actual not in wanted:
                score -= 35
                reasons.append("target scope may not match stated intent")
            else:
                reasons.append("target appears aligned")
        else:
            score -= 20
            reasons.append("command does not expose an explicit target")
    else:
        reasons.append("no explicit target constraint")

    if parsed["privileged"]:
        score -= 20
        reasons.append("command requests elevated privilege")

    status = "MATCH" if score >= 80 else "UNCERTAIN" if score >= 55 else "MISMATCH"
    return max(score, 0), status, reasons

def impact_analysis(parsed):
    operation = parsed["operation"]
    impact = {
        "files": "unknown" if operation in {"DELETE", "COPY", "MOVE", "CREATE"} else 0,
        "directories": 1 if parsed["paths"] else 0,
        "permissions": 1 if operation == "PERMISSION_CHANGE" else 0,
        "processes": 1 if operation == "PROCESS_CONTROL" else 0,
        "network": 1 if operation == "NETWORK" else 0,
        "configuration": 1 if operation == "SYSTEM_CONFIGURATION" else 0,
        "privilege": "ELEVATED" if parsed["privileged"] else "NORMAL",
        "reversible": operation in {"READ", "CREATE", "COPY"}
    }
    return impact

def decision(risk_level, align_status, confidence, impact):
    if confidence < 0.25:
        return "REVIEW"
    if risk_level == "CRITICAL" or align_status == "MISMATCH":
        return "BLOCK"
    if risk_level == "HIGH" or align_status == "UNCERTAIN":
        return "REVIEW"
    if impact["privilege"] == "ELEVATED":
        return "REVIEW"
    return "ALLOW_AFTER_APPROVAL"

def safer_alternative(parsed, contract):
    op = parsed["operation"]
    target = contract["target"] if contract["target"] != "UNSPECIFIED" else "~/Downloads"
    if op == "DELETE":
        return f"Review the target explicitly before deletion; use a narrowly scoped temporary test directory first (target: {target})."
    if op == "PERMISSION_CHANGE":
        return "Avoid elevated privilege unless required; specify one target file and verify the current permission first."
    if op == "PROCESS_CONTROL":
        return "Identify the exact process first and require explicit approval for termination."
    if op == "NETWORK":
        return "Review destination and data flow first; use a read-only or dry-run operation where supported."
    if op == "SYSTEM_CONFIGURATION":
        return "Create a backup/configuration diff and review the exact setting before applying changes."
    return "Use the narrowest command scope that satisfies the stated intent."

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    start = time.perf_counter()
    parsed = parse_command(req.command)
    if not parsed["valid"]:
        return {"error": parsed["error"]}
    inferred, confidence = infer_intent(req.intent)
    contract = intent_contract(req.intent, inferred, confidence)
    score, level, factors = risk_analysis(parsed)
    align_score, align_status, reasons = alignment(contract, parsed)
    impact = impact_analysis(parsed)
    decision_value = decision(level, align_status, confidence, impact)
    budget_status = "WITHIN_BUDGET"
    if align_status == "MISMATCH" or impact["privilege"] == "ELEVATED" or impact["network"] == 1 and not contract["constraints"]["network"]:
        budget_status = "EXCEEDED"
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    return {
        "intent_contract": contract,
        "parsed_command": parsed,
        "risk": {"score": score, "level": level, "factors": factors},
        "alignment": {"score": align_score, "status": align_status, "reasons": reasons},
        "impact": impact,
        "impact_budget": budget_status,
        "decision": decision_value,
        "safer_alternative": safer_alternative(parsed, contract) if decision_value != "ALLOW_AFTER_APPROVAL" else None,
        "analysis_ms": elapsed
    }

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SafeShell AI"}

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeShell AI — Command Intent Firewall</title>
<style>
:root{--bg:#050914;--panel:#0d1628;--line:#243858;--text:#f5f8ff;--muted:#8fa2c2;--blue:#5b8cff;--cyan:#35d6ff;--green:#27d98b;--yellow:#ffc857;--red:#ff5364}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 10% 0%,rgba(91,140,255,.2),transparent 30%),radial-gradient(circle at 90% 8%,rgba(53,214,255,.1),transparent 25%),var(--bg)}
.header{position:sticky;top:0;z-index:10;background:rgba(5,9,20,.86);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}
.header-inner{max-width:1180px;margin:auto;padding:17px 24px;display:flex;justify-content:space-between;align-items:center}
.brand{display:flex;align-items:center;gap:12px}.shield{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(135deg,#315bdc,#26bce8);box-shadow:0 8px 25px rgba(53,140,255,.25);font-size:21px}.brand-title{font-size:21px;font-weight:850}.brand-sub{font-size:12px;color:var(--muted);margin-top:2px}.status{display:flex;align-items:center;gap:8px;color:#b8c8e5;font-size:11px;font-weight:800;letter-spacing:1px}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px var(--green)}
main{max-width:1180px;margin:auto;padding:42px 24px 70px}.hero{text-align:center;max-width:800px;margin:4px auto 32px}.hero h1{margin:0;font-size:clamp(36px,5vw,58px);line-height:1.05;letter-spacing:-2.5px}.hero h1 span{background:linear-gradient(90deg,#fff,#8cbaff,#49dfff);-webkit-background-clip:text;color:transparent}.hero p{color:var(--muted);font-size:15px;line-height:1.65;margin:15px auto 0}
.workspace{background:linear-gradient(145deg,rgba(18,30,52,.96),rgba(9,17,31,.96));border:1px solid var(--line);border-radius:24px;padding:28px;box-shadow:0 24px 70px rgba(0,0,0,.28)}.input-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.field-label{display:flex;align-items:center;gap:8px;margin-bottom:9px;font-size:12px;font-weight:800;letter-spacing:.7px}.num{width:23px;height:23px;border-radius:7px;display:grid;place-items:center;background:#20365d;color:#8db7ff;font-size:10px}
textarea{width:100%;min-height:122px;resize:vertical;background:#050b17;color:#eef4ff;border:1px solid #2c4165;border-radius:14px;padding:16px;font:14px/1.6 Consolas,"Courier New",monospace;outline:none;transition:.2s}textarea:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(91,140,255,.1)}.command-wrap{position:relative}.command-prefix{position:absolute;left:15px;top:16px;color:var(--cyan);font:bold 14px Consolas,monospace}#command{padding-left:31px}
.analyze-row{display:flex;justify-content:center;margin-top:20px}.analyze{border:0;border-radius:13px;padding:14px 28px;color:#fff;background:linear-gradient(135deg,#587fff,#27c5ed);font-size:14px;font-weight:850;cursor:pointer;box-shadow:0 12px 30px rgba(53,140,255,.24);transition:.2s}.analyze:hover{transform:translateY(-2px);box-shadow:0 16px 38px rgba(53,140,255,.34)}.analyze:disabled{opacity:.6;cursor:wait}
.hidden{display:none!important}.results{margin-top:24px}.decision{border:1px solid var(--line);border-radius:22px;padding:26px;background:linear-gradient(145deg,#101b31,#0b1425);box-shadow:0 20px 60px rgba(0,0,0,.28);margin-bottom:18px}.decision.allow{border-color:rgba(39,217,139,.38)}.decision.review{border-color:rgba(255,200,87,.42)}.decision.block{border-color:rgba(255,83,100,.48)}.decision-top{display:flex;justify-content:space-between;gap:20px}.decision-label{color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;font-size:10px;font-weight:850}.decision-title{font-size:38px;font-weight:900;letter-spacing:-1.5px;margin-top:5px}.decision.allow .decision-title{color:var(--green)}.decision.review .decision-title{color:var(--yellow)}.decision.block .decision-title{color:var(--red)}.decision-desc{color:#aebed9;line-height:1.55;margin-top:6px}.decision-icon{flex:none;width:64px;height:64px;border-radius:19px;display:grid;place-items:center;font-size:30px;background:#172945}.decision.allow .decision-icon{background:rgba(39,217,139,.12)}.decision.review .decision-icon{background:rgba(255,200,87,.12)}.decision.block .decision-icon{background:rgba(255,83,100,.12)}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:11px;margin-top:23px}.metric{background:#070e1c;border:1px solid #1d2c48;border-radius:13px;padding:14px}.metric-name{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px}.metric-value{font-size:21px;font-weight:850;margin-top:5px}
.security-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.panel{background:linear-gradient(145deg,#101a2e,#0b1425);border:1px solid var(--line);border-radius:18px;padding:21px}.panel-head{display:flex;align-items:center;gap:10px;margin-bottom:16px}.panel-icon{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:#1b2e50}.panel h3{margin:0;font-size:15px}.panel-sub{color:var(--muted);font-size:10px;margin-top:3px}.rows{display:grid;gap:9px}.row{display:flex;justify-content:space-between;gap:14px;align-items:center;padding:11px 12px;background:#080f1d;border:1px solid #1b2a44;border-radius:10px}.key{color:#8fa3c5;font-size:11px}.value{font:700 11px Consolas,monospace;text-align:right;word-break:break-word}.good{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--yellow)}.blue{color:#7faaff}
.explain{color:#c1cde1;font-size:13px;line-height:1.7;white-space:pre-line}.alternative{margin-top:17px;border-radius:18px;padding:20px;background:linear-gradient(135deg,rgba(34,76,113,.35),rgba(12,26,47,.8));border:1px solid #28547d}.alt-title{font-size:14px;font-weight:850}.alt-text{color:#9fb1ce;font-size:12px;line-height:1.5;margin-top:9px}
details{margin-top:16px;background:#080f1c;border:1px solid #1d2b45;border-radius:12px;overflow:hidden}summary{padding:12px 15px;cursor:pointer;color:#8fa2c2;font-size:11px;font-weight:750}pre{margin:0;padding:16px;overflow:auto;background:#050a14;color:#cbd9ef;font:11px/1.55 Consolas,"Courier New",monospace}.footer{text-align:center;color:#60718e;font-size:10px;margin-top:26px}

.signature-strip{margin-top:18px;display:flex;justify-content:center;align-items:center;gap:14px;padding:13px 18px;border:1px solid #1c3150;border-radius:15px;background:rgba(6,13,26,.72)}
.sig-item{display:flex;align-items:center;gap:7px;color:#7f92b2;font-size:9px;letter-spacing:.7px}.sig-item b{color:#d9e5f8;font-size:9px}.sig-item span:last-child{color:#61738f}.sig-arrow{color:#405979;font-size:15px}.sig-dot{width:6px;height:6px;border-radius:50%;box-shadow:0 0 9px currentColor}.sig-dot.cyan{color:#35d6ff;background:#35d6ff}.sig-dot.blue{color:#5b8cff;background:#5b8cff}.sig-dot.green{color:#27d98b;background:#27d98b}
.security-overview{display:grid;grid-template-columns:1.35fr 1fr;gap:14px;margin-top:20px}.radar-card,.scope-card{border:1px solid #1d3354;border-radius:16px;background:#070f1e;padding:16px}.radar-head{display:flex;justify-content:space-between;color:#7186a7;font-size:9px;font-weight:850;letter-spacing:1.2px}.radar-head span:last-child{color:#27d98b}.radar{height:180px;position:relative;display:grid;place-items:center;overflow:hidden;margin-top:3px}.radar-ring{position:absolute;border:1px solid rgba(73,130,190,.24);border-radius:50%;aspect-ratio:1}.r1{width:46%}.r2{width:68%}.r3{width:90%}.radar-cross{position:absolute;background:rgba(73,130,190,.16)}.radar-cross.h{height:1px;width:90%}.radar-cross.v{width:1px;height:90%}.radar-sweep{position:absolute;width:45%;height:1px;left:50%;top:50%;transform-origin:left center;background:linear-gradient(90deg,rgba(53,214,255,.9),transparent);animation:sweep 3s linear infinite}.radar-core{width:78px;height:78px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px solid #2d5880;background:rgba(12,34,56,.86);box-shadow:0 0 35px rgba(53,214,255,.12);z-index:2}.radar-core b{font-size:24px}.radar-core small{font-size:8px;color:#6d86a7}@keyframes sweep{to{transform:rotate(360deg)}}.scope-title{font-size:9px;color:#7186a7;font-weight:850;letter-spacing:1.2px;margin-bottom:10px}.scope-row{display:flex;justify-content:space-between;padding:11px 10px;border-bottom:1px solid #14243b;font-size:10px;color:#8094b4}.scope-row:last-child{border-bottom:0}.scope-row b{color:#27d98b;font:800 9px Consolas,monospace}.scope-row b.warn{color:#ffc857}.scope-row b.bad{color:#ff5364}
.decision.allow .radar-core{border-color:rgba(39,217,139,.5)}.decision.review .radar-core{border-color:rgba(255,200,87,.5)}.decision.block .radar-core{border-color:rgba(255,83,100,.55)}
@media(max-width:800px){.security-overview{grid-template-columns:1fr}.signature-strip{gap:7px}.sig-arrow{display:none}.sig-item{flex:1;justify-content:center;flex-wrap:wrap}}
@media(max-width:800px){.header-inner{padding:14px 16px}.brand-sub{display:none}main{padding:28px 14px 50px}.hero h1{font-size:38px}.workspace{padding:18px}.input-grid,.security-grid,.metrics{grid-template-columns:1fr}.decision-top{flex-direction:column}.decision-icon{width:54px;height:54px}.decision-title{font-size:31px}}
</style>
</head>
<body>
<header class="header"><div class="header-inner">
  <div class="brand"><div class="shield">🛡</div><div><div class="brand-title">SafeShell AI</div><div class="brand-sub">Intent Firewall · Command Safety Intelligence</div></div></div>
  <div class="status"><span class="dot"></span> PROTECTION ACTIVE</div>
</div></header>

<main>
<section class="hero"><h1><span>Intent</span> before consequences.</h1><p>A local-first security layer that translates human intent into a safety contract, inspects command behavior, and stops dangerous mismatches before execution.</p></section>

<section class="workspace">
  <div class="input-grid">
    <div><div class="field-label"><span class="num">01</span> YOUR INTENT</div><textarea id="intent">I want to view files in ~/Downloads</textarea></div>
    <div><div class="field-label"><span class="num">02</span> COMMAND TO ANALYZE</div><div class="command-wrap"><span class="command-prefix">$</span><textarea id="command">ls -la ~/Downloads</textarea></div></div>
  </div>
  <div class="analyze-row"><button class="analyze" id="analyzeBtn" onclick="analyze()">🛡 ANALYZE COMMAND</button></div>
</section>

<section id="results" class="results hidden">
  <div id="decision" class="decision">
    <div class="decision-top"><div><div class="decision-label">Security Decision</div><div id="decisionTitle" class="decision-title">ANALYZING</div><div id="decisionDesc" class="decision-desc">Evaluating intent, command impact and policy.</div></div><div id="decisionIcon" class="decision-icon">🔍</div></div>
    <div class="metrics">
      <div class="metric"><div class="metric-name">Risk Score</div><div id="riskValue" class="metric-value">—</div></div>
      <div class="metric"><div class="metric-name">Intent Alignment</div><div id="alignValue" class="metric-value">—</div></div>
      <div class="metric"><div class="metric-name">Privilege</div><div id="privValue" class="metric-value">—</div></div>
    </div>

<div class="security-overview">
  <div class="radar-card">
    <div class="radar-head"><span>THREAT RADAR</span><span id="riskLabel">LOW</span></div>
    <div class="radar">
      <div class="radar-ring r1"></div><div class="radar-ring r2"></div><div class="radar-ring r3"></div>
      <div class="radar-cross h"></div><div class="radar-cross v"></div>
      <div id="radarSweep" class="radar-sweep"></div>
      <div id="radarCore" class="radar-core"><b id="radarScore">0</b><small>/100</small></div>
    </div>
  </div>
  <div class="scope-card">
    <div class="scope-title">SECURITY POSTURE</div>
    <div class="scope-row"><span>Filesystem</span><b id="postureFs">SCOPED</b></div>
    <div class="scope-row"><span>Network</span><b id="postureNet">SAFE</b></div>
    <div class="scope-row"><span>Privilege</span><b id="posturePriv">NORMAL</b></div>
    <div class="scope-row"><span>Policy Budget</span><b id="postureBudget">WITHIN</b></div>
  </div>
</div>
  </div>

  <div class="security-grid">
    <div class="panel"><div class="panel-head"><div class="panel-icon">🧠</div><div><h3>Intent Contract</h3><div class="panel-sub">What the user requested</div></div></div>
      <div class="rows">
        <div class="row"><span class="key">Operation</span><span id="intentOp" class="value blue">—</span></div>
        <div class="row"><span class="key">Target</span><span id="intentTarget" class="value">—</span></div>
        <div class="row"><span class="key">Modification</span><span id="intentMod" class="value">—</span></div>
        <div class="row"><span class="key">Network</span><span id="intentNet" class="value">—</span></div>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><div class="panel-icon">🔍</div><div><h3>Command Analysis</h3><div class="panel-sub">What the command attempts</div></div></div>
      <div class="rows">
        <div class="row"><span class="key">Operation</span><span id="cmdOp" class="value blue">—</span></div>
        <div class="row"><span class="key">Target</span><span id="cmdTarget" class="value">—</span></div>
        <div class="row"><span class="key">Destructive</span><span id="cmdDestructive" class="value">—</span></div>
        <div class="row"><span class="key">Network</span><span id="cmdNetwork" class="value">—</span></div>
      </div>
    </div>
  </div>

  <div class="panel" style="margin-top:17px"><div class="panel-head"><div class="panel-icon">💡</div><div><h3>Security Explanation</h3><div class="panel-sub">Why SafeShell reached this decision</div></div></div><div id="explanation" class="explain">Waiting for analysis.</div></div>

  <div id="alternative" class="alternative hidden"><div class="alt-title">🛡 Safer Guidance</div><div id="alternativeText" class="alt-text"></div></div>

  <details><summary>ADVANCED ANALYSIS DATA</summary><pre id="rawData"></pre></details>
</section>

<div class="signature-strip">
  <div class="sig-item"><span class="sig-dot cyan"></span><b>INTENT</b><span>understood</span></div>
  <div class="sig-arrow">→</div>
  <div class="sig-item"><span class="sig-dot blue"></span><b>COMMAND</b><span>inspected</span></div>
  <div class="sig-arrow">→</div>
  <div class="sig-item"><span class="sig-dot green"></span><b>POLICY</b><span>enforced</span></div>
</div>
<div class="footer">SafeShell AI · Intent Firewall · Local-first command safety intelligence</div>
</main>

<script>
function text(v){if(v===undefined||v===null)return"—";if(Array.isArray(v))return v.length?v.join(", "):"None";if(typeof v==="object")return JSON.stringify(v);return String(v)}
function set(id,v){const e=document.getElementById(id);if(e)e.textContent=text(v)}
function decisionInfo(raw){const d=String(raw||"").toUpperCase();if(d==="BLOCK")return["BLOCK","block","×","The command violates the current safety boundary and should not proceed."];if(d==="REVIEW")return["REVIEW","review","!","The command requires human review before execution."];if(d==="ALLOW_AFTER_APPROVAL")return["ALLOW AFTER APPROVAL","review","✓","The command is within the current safety budget but requires explicit approval."];return[d||"REVIEW","review","!","SafeShell could not classify the decision confidently."]}
function color(id,v){const e=document.getElementById(id);if(!e)return;e.classList.remove("good","bad","warn");const s=String(v).toUpperCase();if(s==="TRUE"||s.includes("FORBIDDEN")||s.includes("ELEVATED"))e.classList.add("bad");else if(s==="FALSE"||s.includes("NORMAL")||s.includes("ALLOWED"))e.classList.add("good");else if(s.includes("REVIEW")||s.includes("REQUIRES"))e.classList.add("warn")}

async function analyze(){
  const intent=document.getElementById("intent").value.trim(),command=document.getElementById("command").value.trim(),btn=document.getElementById("analyzeBtn");
  if(!intent||!command){alert("Please enter both your intent and the Linux command.");return}
  btn.disabled=true;btn.textContent="⏳ ANALYZING...";document.getElementById("results").classList.remove("hidden");
  try{
    const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({intent:intent,command:command})});
    const d=await r.json();if(!r.ok||d.error)throw new Error(d.error||"Analysis failed.");
    const info=decisionInfo(d.decision),card=document.getElementById("decision");
    card.className="decision "+info[1];set("decisionTitle",info[0]);set("decisionDesc",info[3]);set("decisionIcon",info[2]);
    set("riskValue",(d.risk.score||0)+"/100");set("alignValue",(d.alignment.score||0)+"/100");set("privValue",d.impact.privilege||"NORMAL");
    set("radarScore",d.risk.score||0); set("riskLabel",d.risk.level||"LOW");
    set("posturePriv",d.impact.privilege||"NORMAL");
    set("postureNet",d.impact.network===1?"REVIEW":"SAFE");
    set("postureBudget",d.impact_budget==="EXCEEDED"?"EXCEEDED":"WITHIN");
    const rl=document.getElementById("riskLabel"), rs=document.getElementById("radarScore");
    rl.className=""; rs.className="";
    if((d.risk.score||0)>=50){rl.className="bad";rs.className="bad"} else if((d.risk.score||0)>=25){rl.className="warn";rs.className="warn"}
    color("posturePriv",d.impact.privilege); color("postureNet",d.impact.network===1?"REVIEW":"SAFE"); color("postureBudget",d.impact_budget);

    const p=d.parsed_command||{};
const c=d.intent_contract||{},x=c.constraints||{};
    set("intentOp",c.operation);set("intentTarget",c.target);set("intentMod",x.modification);set("intentNet",x.network);
    set("cmdOp",p.operation);set("cmdTarget",p.paths&&p.paths.length?p.paths.join(", "):"UNSPECIFIED");
    const destructive=["DELETE","PERMISSION_CHANGE","SYSTEM_CONFIGURATION","PACKAGE_CHANGE"].includes(p.operation);
    set("cmdDestructive",destructive?"TRUE":"FALSE");set("cmdNetwork",p.operation==="NETWORK"?"TRUE":"FALSE");
    color("intentMod",x.modification);color("intentNet",x.network);color("cmdDestructive",destructive);color("cmdNetwork",p.operation==="NETWORK");
    const reasons=(d.risk.factors||[]).map(x=>"• "+x),align=(d.alignment.reasons||[]).map(x=>"• "+x);
    document.getElementById("explanation").textContent=(reasons.concat(align)).join("\n")||"✓ Intent and command are aligned.\n✓ No significant risk indicators were detected.";
    const alt=document.getElementById("alternative");
    if(d.safer_alternative){alt.classList.remove("hidden");document.getElementById("alternativeText").textContent=d.safer_alternative}else alt.classList.add("hidden");
    document.getElementById("rawData").textContent=JSON.stringify(d,null,2);
    document.getElementById("results").scrollIntoView({behavior:"smooth",block:"start"});
  }catch(err){
    const card=document.getElementById("decision");card.className="decision block";set("decisionTitle","ANALYSIS ERROR");set("decisionDesc",err.message);set("decisionIcon","!");document.getElementById("explanation").textContent="The request could not be completed. Check that the SafeShell server is running.";
  }finally{btn.disabled=false;btn.textContent="🛡 ANALYZE COMMAND"}
}
</script>
</body>
</html>
"""