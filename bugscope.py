#!/usr/bin/env python3
"""
BugScope: GitHub Commit Monitor

Monitors target repos for new commits, filters by security-relevant keywords.

Author: kanyo
"""

import os
import sys
import json
import time
import hashlib
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
STATE_FILE = SCRIPT_DIR / "state.json"
LOG_FILE = SCRIPT_DIR / "bugscope.log"
FLAGGED_LOG = SCRIPT_DIR / "flagged.jsonl"

# Repos to monitor: (owner, repo, branch)
TARGETS = [
    # Add Targets Here
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
    # Memory safety (C/C++)
    "buffer", "overflow", "underflow", "malloc", "free(", "realloc",
    "memmove", "memcpy", "strlen", "INSIST", "assert",
    # Crypto / validation
    "validate", "verify", "signature", "nonce", "replay", "hash",
    "encrypt", "decrypt", "cipher", "hmac",
    # Permissions
    "permission", "privilege", "escalat", "chmod", "chown", "setuid",
    "capability", "sandbox",
]

KEYWORD_THRESHOLD = 2

USE_LLM = True

MAX_DIFF_CHARS = 12000

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
    """Load .env file if present."""
    env_file = SCRIPT_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


load_env()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# ---------------------------------------------------------------------------
# State management
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
    """Fetch recent commits from a repo."""
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
    """Fetch the diff for a specific commit."""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    headers = {**GH_HEADERS, "Accept": "application/vnd.github.v3.diff"}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        log.error(f"Diff fetch error for {owner}/{repo}@{sha}: {e}")
    return ""


# ---------------------------------------------------------------------------
# Keyword analysis
# ---------------------------------------------------------------------------


def keyword_scan(diff: str, message: str) -> list:
    """Scan diff and commit message for security keywords. Returns matched keywords."""
    text = (diff + "\n" + message).lower()
    matched = []
    for kw in KEYWORDS:
        if kw.lower() in text:
            matched.append(kw)
    return list(set(matched))


# ---------------------------------------------------------------------------
# Groq LLM triage
# ---------------------------------------------------------------------------

TRIAGE_PROMPT = """You are a security researcher triaging a code commit for potential vulnerabilities.

Analyze this commit diff and determine if it introduces or touches security-relevant code.

Focus on:
- Command injection / code execution vectors
- Authentication or authorization changes
- Path traversal / symlink handling
- Prototype pollution / object injection
- Memory safety issues (buffer overflows, use-after-free)
- Race conditions / TOCTOU
- Cryptographic weaknesses
- Input validation gaps

Respond with ONLY a JSON object (no markdown, no backticks):
{{
  "interesting": true/false,
  "confidence": "high"/"medium"/"low",
  "category": "short category name",
  "summary": "1-2 sentence explanation of what's security-relevant, or why it's not interesting"
}}

COMMIT MESSAGE: {message}

DIFF (truncated):
{diff}"""

LLM_CHAIN = [
    {
        "name": "GitHub Models (GPT-4.1-mini)",
        "url": "https://models.github.ai/inference/chat/completions",
        "key_env": "GITHUB_TOKEN",
        "model": "openai/gpt-4.1-mini",
        "extra_headers": {},
    },
    {
    "name": "NVIDIA NIM (Devstral 2 123B)",
    "url": "https://integrate.api.nvidia.com/v1/chat/completions",
    "key_env": "NVIDIA_API_KEY",
    "model": "mistralai/devstral-2-123b-instruct-2512",
    "extra_headers": {},
    },
    {
        "name": "Groq (llama-3.3-70b)",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "key_env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
        "extra_headers": {},
    },
]


def _call_llm(provider: dict, message: str, diff: str) -> dict | None:
    """Call a single LLM provider."""
    api_key = os.environ.get(provider["key_env"], "")
    if not api_key:
        return None

    truncated_diff = diff[:MAX_DIFF_CHARS]
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        **provider.get("extra_headers", {}),
    }

    try:

        body = {
            "model": provider["model"],
            "messages": [
                {
                    "role": "user",
                    "content": TRIAGE_PROMPT.format(message=message, diff=truncated_diff),
                }
            ],
        }
        if "github.ai" in provider["url"]:
            body["max_completion_tokens"] = 1024
        else:
            body["max_tokens"] = 300
            body["temperature"] = 0.1

 
        resp = requests.post(
            provider["url"],
            headers=headers,
            json=body,
            timeout=60,
        )

        if resp.status_code == 200:
            resp_json = resp.json()
            # Handle different response structures
            try:
                content = resp_json["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError):
                log.warning(f"{provider['name']} unexpected response structure: {json.dumps(resp_json)[:300]}")
                return None

            if content is None:
                # Reasoning models (e.g. StepFun) may put output in reasoning_content
                try:
                    content = resp_json["choices"][0]["message"].get("reasoning_content", "")
                except (KeyError, IndexError, TypeError):
                    pass
                if not content:
                    log.warning(f"{provider['name']} returned null content")
                    return None

            log.debug(f"{provider['name']} raw response: {content[:500]}")
            content = content.strip()
            # Clean potential markdown wrapping and thinking tags
            content = content.replace("```json", "").replace("```", "").strip()
            # Handle Qwen3's <think>...</think> tags
            if "</think>" in content:
                content = content.split("</think>")[-1].strip()
            # Extract JSON object if there's extra text around it
            if "{" in content:
                start = content.index("{")
                end = content.rindex("}") + 1
                content = content[start:end]

            result = json.loads(content)
            result["_provider"] = provider["name"]
            return result
        else:
            log.warning(f"{provider['name']} API {resp.status_code}: {resp.text[:200]}")
    except json.JSONDecodeError as e:
        log.warning(f"{provider['name']} parse error: {e}")
    except Exception as e:
        log.error(f"{provider['name']} error: {e}")

    return None


def llm_triage(message: str, diff: str) -> dict:
    """Triage a commit diff using LLM chain."""
    if not OPENROUTER_API_KEY and not GROQ_API_KEY:
        return {"interesting": True, "confidence": "unknown", "category": "no-llm", "summary": "No LLM configured, passing through"}

    for provider in LLM_CHAIN:
        result = _call_llm(provider, message, diff)
        if result is not None:
            log.info(f"  LLM triage via {provider['name']}")
            return result

    return {"interesting": True, "confidence": "unknown", "category": "llm-error", "summary": "All LLM providers failed, passing through"}


# ---------------------------------------------------------------------------
# Telegram alerts
# ---------------------------------------------------------------------------


def send_telegram(text: str):
    """Send a message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram not configured, printing alert to stdout")
        print(f"\n🚨 ALERT:\n{text}\n")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    if len(text) > 4000:
        text = text[:3997] + "..."

    try:
        resp = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
        if resp.status_code != 200:
            log.warning(f"Telegram API {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log.error(f"Telegram error: {e}")


# ---------------------------------------------------------------------------
# Alert formatting
# ---------------------------------------------------------------------------


def format_alert(owner: str, repo: str, commit: dict, keywords: list, llm_result: dict) -> str:
    sha = commit["sha"][:8]
    message = commit["commit"]["message"].split("\n")[0][:100]
    author = commit["commit"]["author"]["name"]
    url = commit["html_url"]
    kw_str = ", ".join(keywords[:10])

    llm_verdict = ""
    if llm_result and llm_result.get("category") != "no-llm":
        conf = llm_result.get("confidence", "?")
        cat = llm_result.get("category", "?")
        summary = llm_result.get("summary", "")
        llm_verdict = f"\n <b>LLM ({llm_result.get('_provider', '?')}):</b> [{conf}] {cat}\n{summary}"

    return (
        f"🔍 <b> Target: {owner}/{repo} </b>\n"
        f"<b>Commit:</b> <code>{sha}</code> by {author}\n"
        f"<b>Message:</b> {message}\n"
        f"<b>Keywords:</b> {kw_str}\n"
        f"{llm_verdict}\n"
        f"🔗 {url}"
    )


# ---------------------------------------------------------------------------
# Flagged commit logging
# ---------------------------------------------------------------------------


def log_flagged(owner: str, repo: str, commit: dict, keywords: list, llm_result: dict):
    """Append flagged commit to JSONL log for later review."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": f"{owner}/{repo}",
        "sha": commit["sha"],
        "message": commit["commit"]["message"].split("\n")[0],
        "url": commit["html_url"],
        "keywords": keywords,
        "llm": llm_result,
    }
    with open(FLAGGED_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def process_repo(owner: str, repo: str, branch: str, state: dict) -> int:
    """Process a single repo. Returns number of alerts sent."""
    repo_key = f"{owner}/{repo}"
    last_sha = state.get(repo_key)
    alerts = 0

    # Fetch commits since last check (or last 6 hours on first run)
    since = None
    if not last_sha:
        since = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()

    commits = get_commits(owner, repo, branch, since)
    if not commits:
        return 0

    # Update state to latest commit
    state[repo_key] = commits[0]["sha"]

    # Process new commits (skip if we've seen the latest)
    new_commits = []
    for c in commits:
        if c["sha"] == last_sha:
            break
        new_commits.append(c)

    if not new_commits:
        return 0

    log.info(f"{repo_key}: {len(new_commits)} new commit(s)")

    for commit in reversed(new_commits):  # oldest first
        sha = commit["sha"]
        message = commit["commit"]["message"]

        # Stage 1: Fetch diff
        diff = get_commit_diff(owner, repo, sha)
        if not diff:
            continue

        # Stage 2: Keyword filter
        keywords = keyword_scan(diff, message)
        if len(keywords) < KEYWORD_THRESHOLD:
            continue

        log.info(f"  [{sha[:8]}] Keyword hit ({len(keywords)}): {', '.join(keywords[:5])}")

        # Stage 3: LLM triage (optional)
        llm_result = {}
        if USE_LLM:
            llm_result = llm_triage(message, diff)
            if not llm_result.get("interesting", True):
                log.info(f"  [{sha[:8]}] LLM says not interesting, logging anyway")
                log_flagged(owner, repo, commit, keywords, llm_result)
                continue

        # Stage 4: Alert
        alert_text = format_alert(owner, repo, commit, keywords, llm_result)
        send_telegram(alert_text)
        log_flagged(owner, repo, commit, keywords, llm_result)
        alerts += 1

        time.sleep(1)

    return alerts


def main():
    log.info("BugScope starting")

    state = load_state()
    total_alerts = 0

    for owner, repo, branch in TARGETS:
        try:
            alerts = process_repo(owner, repo, branch, state)
            total_alerts += alerts
        except Exception as e:
            log.error(f"Error processing {owner}/{repo}: {e}")

        time.sleep(0.5 if GITHUB_TOKEN else 2)

    save_state(state)
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        send_telegram(f"<b>BugScope done.</b> {total_alerts} alert(s) | {now}")
    log.info(f"Done. {total_alerts} alert(s) sent.")


if __name__ == "__main__":
    main()
