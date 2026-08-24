#!/usr/bin/env python3
"""
BugScope: GitHub Commit Monitor

Monitors target repos for new commits, filters by security-relevant keywords,
then runs deep security assessment via Claude Code CLI using per-target
scope, guidelines, and persistent repo context.

Author: kanyo
"""

import os
import sys
import json
import time
import logging
import subprocess
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
STATE_FILE = SCRIPT_DIR / "state.json"
LOG_FILE   = SCRIPT_DIR / "bugscope.log"
FLAGGED_LOG = SCRIPT_DIR / "flagged.jsonl"

# Root directories — create these on your machine before running
BUGS_DIR    = Path("/bugs")
REPOS_DIR   = BUGS_DIR / "repos"
TARGETS_DIR = BUGS_DIR / "targets"

# Repos to monitor: (owner, repo, branch, target_name)
# target_name maps to /bugs/targets/<target_name>/
TARGETS = [
    # ("owner", "repo", "main", "target-name"),
]

KEYWORDS = [
    # Command injection
    "shell", "exec", "spawn", "child_process", "popen", "system(",
    "subprocess", "spawnSync", "execSync",
    # Auth / secrets
    "auth", "basicAuth", "password", "token", "cookie", "session",
    "credential", "secret", "apikey", "api_key", "jwt", "oauth",
    "bearer", "login", "logout", "signin", "signup",
    # Routing / network
    "proxy", "redirect", "cors", "origin", "forwarded", "header",
    "websocket", "upgrade",
    # Path / filesystem
    "path", "traversal", "symlink", "readlink", "../", "normalize",
    "resolve(", "join(",
    # Prototype pollution
    "prototype", "__proto__", "constructor", "merge", "Object.assign",
    "deepmerge",
    # Memory safety
    "buffer", "overflow", "underflow", "malloc", "free(", "realloc",
    "memmove", "memcpy", "strlen", "INSIST", "assert",
    # Crypto / validation
    "validate", "verify", "signature", "nonce", "replay", "hash",
    "encrypt", "decrypt", "cipher", "hmac",
    # Permissions
    "permission", "privilege", "escalat", "chmod", "chown", "setuid",
    "capability", "sandbox",
    # SSRF / URL fetching
    "fetch(", "request(", "http.get", "urllib", "axios", "got(",
    "url", "endpoint", "webhook", "curl",
    # Deserialization
    "deserializ", "pickle", "marshal", "yaml.load", "JSON.parse",
    "unserializ", "fromJson",
    # SQL
    "query(", "execute(", "raw(", "SELECT", "INSERT", "UPDATE", "DELETE",
    "WHERE", "sqlite", "mysql", "postgres",
]

KEYWORD_THRESHOLD = 2
USE_CLAUDE_CODE   = True   # primary: Claude Code CLI
USE_LLM_FALLBACK  = True   # fallback if Claude Code unavailable
MAX_DIFF_CHARS    = 15000

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("bugscope")

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def load_env():
    env_file = SCRIPT_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

load_env()

GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID  = os.environ.get("TELEGRAM_CHAT_ID", "")
GROQ_API_KEY      = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# ---------------------------------------------------------------------------
# Target context
# ---------------------------------------------------------------------------

def load_target_context(target_name: str) -> dict:
    """Load scope, guidelines, and repo context for a target."""
    target_dir = TARGETS_DIR / target_name
    ctx = {"scope": "", "guidelines": "", "context": "", "reports_summary": ""}

    if not target_dir.exists():
        log.warning(f"Target dir not found: {target_dir} — running without context")
        return ctx

    for key, filename in [("scope", "scope.md"), ("guidelines", "guidelines.md"), ("context", "context.md")]:
        f = target_dir / filename
        if f.exists():
            ctx[key] = f.read_text()

    reports_dir = target_dir / "reports"
    if reports_dir.exists():
        reports = []
        for f in sorted(reports_dir.glob("*.md"))[-5:]:
            first_line = f.read_text().split("\n")[0] if f.stat().st_size > 0 else ""
            reports.append(f"- {f.name}: {first_line}")
        ctx["reports_summary"] = "\n".join(reports)

    return ctx


def update_context(target_name: str, owner: str, repo: str, sha: str, assessment: str):
    """Append commit assessment summary to /bugs/targets/<target>/context.md."""
    context_file = TARGETS_DIR / target_name / "context.md"
    if not context_file.parent.exists():
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = f"\n## Commit {sha[:8]} — {now}\n{assessment[:500]}\n"

    if not context_file.exists():
        header = (
            f"# Repo Context: {owner}/{repo}\n\n"
            "Auto-maintained by BugScope. Add architecture notes, auth flow details,\n"
            "and known sensitive areas above the log section.\n\n"
            "---\n## Analyzed Commits Log\n"
        )
        context_file.write_text(header + entry)
    else:
        with open(context_file, "a") as f:
            f.write(entry)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------

GH_HEADERS = {"Accept": "application/vnd.github.v3+json"}
if GITHUB_TOKEN:
    GH_HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"


def get_commits(owner: str, repo: str, branch: str, since: Optional[str] = None) -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": branch, "per_page": 20}
    if since:
        params["since"] = since
    try:
        resp = requests.get(url, headers=GH_HEADERS, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        log.warning(f"GitHub API {resp.status_code} for {owner}/{repo}: {resp.text[:200]}")
    except Exception as e:
        log.error(f"GitHub API error for {owner}/{repo}: {e}")
    return []


def get_commit_diff(owner: str, repo: str, sha: str) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {**GH_HEADERS, "Accept": "application/vnd.github.v3.diff"}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        log.error(f"Diff fetch error for {owner}/{repo}@{sha}: {e}")
    return ""


def clone_or_update_repo(owner: str, repo: str) -> Optional[Path]:
    """Clone repo to /bugs/repos/ or pull if already cloned."""
    repo_path = REPOS_DIR / f"{owner}__{repo}"
    clone_url = f"https://github.com/{owner}/{repo}.git"
    if GITHUB_TOKEN:
        clone_url = f"https://{GITHUB_TOKEN}@github.com/{owner}/{repo}.git"

    try:
        if repo_path.exists():
            result = subprocess.run(
                ["git", "-C", str(repo_path), "pull", "--quiet"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                log.warning(f"git pull failed: {result.stderr[:200]}")
        else:
            result = subprocess.run(
                ["git", "clone", "--depth=50", "--quiet", clone_url, str(repo_path)],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                log.warning(f"git clone failed: {result.stderr[:200]}")
                return None
        return repo_path
    except Exception as e:
        log.error(f"Clone/pull error for {owner}/{repo}: {e}")
        return None

# ---------------------------------------------------------------------------
# Keyword scan
# ---------------------------------------------------------------------------

def keyword_scan(diff: str, message: str) -> list:
    text = (diff + "\n" + message).lower()
    return list(set(kw for kw in KEYWORDS if kw.lower() in text))

# ---------------------------------------------------------------------------
# Claude Code assessment
# ---------------------------------------------------------------------------

CLAUDE_PROMPT = """You are a security researcher performing a bug bounty audit.

## Program Scope
{scope}

## Hunting Guidelines
{guidelines}

## Repo Context
{context}

## Past Reports
{reports_summary}

## Commit
Repository: {owner}/{repo}
SHA: {sha}
Message: {message}
Author: {author}
Date: {date}
Matched Keywords: {keywords}

## Diff
{diff}

## Task
Analyze this diff for security vulnerabilities. Think like an attacker.

For each finding:
- **Vuln Class** (SSRF, SQLi, RCE, auth bypass, path traversal, IDOR, etc.)
- **File & Line**
- **Attack Scenario** — exact exploitation steps
- **Severity** — Critical / High / Medium / Low / Info
- **In Scope?** — check against program scope
- **Confidence** — High / Medium / Low
- **Evidence** — quote the vulnerable code

If nothing interesting: respond with exactly `CLEAN: <reason>`

Rules:
- Never hallucinate. Unsure = Low confidence.
- Flag partial sinks needing manual tracing.
- Don't re-flag issues already in past reports.
- Consider chaining — a low-severity primitive that enables a higher-severity bug is worth flagging.
"""


def claude_code_assess(owner, repo, sha, message, author, date, diff, keywords, ctx) -> str:
    prompt = CLAUDE_PROMPT.format(
        scope=ctx["scope"] or "No scope file — apply general bug bounty judgment.",
        guidelines=ctx["guidelines"] or "Focus on OWASP Top 10 and common web vulnerabilities.",
        context=ctx["context"] or "No prior context — first analyzed commit.",
        reports_summary=ctx["reports_summary"] or "No past reports.",
        owner=owner, repo=repo, sha=sha, message=message,
        author=author, date=date,
        keywords=", ".join(keywords),
        diff=diff[:MAX_DIFF_CHARS],
    )
    try:
        result = subprocess.run(
            ["claude", "-p", prompt],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        log.warning(f"Claude Code non-zero or empty: {result.stderr[:200]}")
    except FileNotFoundError:
        log.error("claude CLI not found — install: npm install -g @anthropic-ai/claude-code")
    except subprocess.TimeoutExpired:
        log.error("Claude Code timed out")
    except Exception as e:
        log.error(f"Claude Code error: {e}")
    return ""

# ---------------------------------------------------------------------------
# LLM fallback chain
# ---------------------------------------------------------------------------

TRIAGE_PROMPT = """You are a security researcher triaging a code commit.

Analyze this diff for security-relevant changes: command injection, auth/authz,
path traversal, prototype pollution, memory safety, SSRF, SQLi, crypto weaknesses.

Respond ONLY with a JSON object, no markdown:
{{"interesting": true/false, "confidence": "high"/"medium"/"low", "category": "short name", "summary": "1-2 sentences"}}

COMMIT: {message}
DIFF:
{diff}"""

LLM_CHAIN = [
    {"name": "GitHub Models (GPT-4.1-mini)", "url": "https://models.github.ai/inference/chat/completions",
     "key_env": "GITHUB_TOKEN", "model": "openai/gpt-4.1-mini"},
    {"name": "NVIDIA NIM (Devstral 2)", "url": "https://integrate.api.nvidia.com/v1/chat/completions",
     "key_env": "NVIDIA_API_KEY", "model": "mistralai/devstral-2-123b-instruct-2512"},
    {"name": "Groq (llama-3.3-70b)", "url": "https://api.groq.com/openai/v1/chat/completions",
     "key_env": "GROQ_API_KEY", "model": "llama-3.3-70b-versatile"},
]


def _call_llm(provider: dict, message: str, diff: str) -> Optional[dict]:
    api_key = os.environ.get(provider["key_env"], "")
    if not api_key:
        return None
    try:
        resp = requests.post(
            provider["url"],
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": provider["model"], "max_tokens": 300, "temperature": 0.1,
                  "messages": [{"role": "user", "content": TRIAGE_PROMPT.format(
                      message=message, diff=diff[:MAX_DIFF_CHARS])}]},
            timeout=60,
        )
        if resp.status_code == 200:
            content = resp.json()["choices"][0]["message"]["content"] or ""
            content = content.strip().replace("```json", "").replace("```", "").strip()
            if "</think>" in content:
                content = content.split("</think>")[-1].strip()
            if "{" in content:
                content = content[content.index("{"):content.rindex("}")+1]
            result = json.loads(content)
            result["_provider"] = provider["name"]
            return result
        log.warning(f"{provider['name']} {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log.error(f"{provider['name']} error: {e}")
    return None


def llm_triage(message: str, diff: str) -> dict:
    for provider in LLM_CHAIN:
        result = _call_llm(provider, message, diff)
        if result:
            log.info(f"  LLM triage via {provider['name']}")
            return result
    return {"interesting": True, "confidence": "unknown", "category": "llm-error",
            "summary": "All providers failed — flagged for manual review"}

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

def send_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"\n🚨 ALERT:\n{text}\n")
        return
    if len(text) > 4000:
        text = text[:3997] + "..."
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text,
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=10,
        )
        if resp.status_code != 200:
            log.warning(f"Telegram {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log.error(f"Telegram error: {e}")

# ---------------------------------------------------------------------------
# Alert formatting
# ---------------------------------------------------------------------------

def format_alert(owner, repo, commit, keywords, assessment, llm_result) -> str:
    sha     = commit["sha"][:8]
    message = commit["commit"]["message"].split("\n")[0][:100]
    author  = commit["commit"]["author"]["name"]
    url     = commit["html_url"]
    kw_str  = ", ".join(keywords[:10])

    if assessment:
        body = f"\n\n<b>Assessment:</b>\n<pre>{assessment[:1500]}{'...' if len(assessment) > 1500 else ''}</pre>"
    elif llm_result:
        body = (f"\n\n<b>LLM ({llm_result.get('_provider','?')}):</b> "
                f"[{llm_result.get('confidence','?')}] {llm_result.get('category','?')}\n"
                f"{llm_result.get('summary','')}")
    else:
        body = ""

    return (
        f"🔍 <b>{owner}/{repo}</b>\n"
        f"<b>Commit:</b> <code>{sha}</code> by {author}\n"
        f"<b>Message:</b> {message}\n"
        f"<b>Keywords:</b> {kw_str}"
        f"{body}\n\n"
        f"🔗 {url}"
    )

# ---------------------------------------------------------------------------
# Flagged log
# ---------------------------------------------------------------------------

def log_flagged(owner, repo, commit, keywords, assessment, llm_result):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": f"{owner}/{repo}",
        "sha": commit["sha"],
        "message": commit["commit"]["message"].split("\n")[0],
        "url": commit["html_url"],
        "keywords": keywords,
        "claude_assessment": assessment,
        "llm": llm_result,
    }
    with open(FLAGGED_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_repo(owner, repo, branch, target_name, state) -> int:
    repo_key = f"{owner}/{repo}"
    last_sha = state.get(repo_key)
    alerts   = 0

    since = None
    if not last_sha:
        since = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()

    commits = get_commits(owner, repo, branch, since)
    if not commits:
        return 0

    state[repo_key] = commits[0]["sha"]

    new_commits = []
    for c in commits:
        if c["sha"] == last_sha:
            break
        new_commits.append(c)

    if not new_commits:
        return 0

    log.info(f"{repo_key}: {len(new_commits)} new commit(s)")

    ctx = load_target_context(target_name)
    clone_or_update_repo(owner, repo)

    for commit in reversed(new_commits):
        sha     = commit["sha"]
        message = commit["commit"]["message"]
        author  = commit["commit"]["author"]["name"]
        date    = commit["commit"]["author"]["date"]

        diff = get_commit_diff(owner, repo, sha)
        if not diff:
            continue

        keywords = keyword_scan(diff, message)
        if len(keywords) < KEYWORD_THRESHOLD:
            continue

        log.info(f"  [{sha[:8]}] Keywords ({len(keywords)}): {', '.join(keywords[:5])}")

        assessment = ""
        llm_result = {}

        if USE_CLAUDE_CODE:
            log.info(f"  [{sha[:8]}] Claude Code assessing...")
            assessment = claude_code_assess(owner, repo, sha, message, author, date, diff, keywords, ctx)

            if assessment:
                update_context(target_name, owner, repo, sha, assessment)
                if assessment.strip().upper().startswith("CLEAN:"):
                    log.info(f"  [{sha[:8]}] CLEAN — skipping alert")
                    log_flagged(owner, repo, commit, keywords, assessment, {})
                    continue
            elif USE_LLM_FALLBACK:
                log.info(f"  [{sha[:8]}] Claude unavailable, falling back to LLM chain")
                llm_result = llm_triage(message, diff)
                if not llm_result.get("interesting", True):
                    log_flagged(owner, repo, commit, keywords, "", llm_result)
                    continue
        elif USE_LLM_FALLBACK:
            llm_result = llm_triage(message, diff)
            if not llm_result.get("interesting", True):
                log_flagged(owner, repo, commit, keywords, "", llm_result)
                continue

        alert = format_alert(owner, repo, commit, keywords, assessment, llm_result)
        send_telegram(alert)
        log_flagged(owner, repo, commit, keywords, assessment, llm_result)
        alerts += 1
        time.sleep(1)

    return alerts


def main():
    log.info("BugScope starting")
    state = load_state()
    total = 0

    for entry in TARGETS:
        owner, repo, branch, target_name = entry
        try:
            total += process_repo(owner, repo, branch, target_name, state)
        except Exception as e:
            log.error(f"Error processing {owner}/{repo}: {e}")
        time.sleep(0.5 if GITHUB_TOKEN else 2)

    save_state(state)
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        send_telegram(f"<b>BugScope done.</b> {total} alert(s) | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log.info(f"Done. {total} alert(s) sent.")


if __name__ == "__main__":
    main()
