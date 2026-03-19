# BugScope

GitHub commit monitor. Watches target repos for security-relevant changes.

## How It Works

```
  → Poll GitHub API for new commits
  → Fetch diffs
  → Stage 1: Keyword filter (auth, exec, shell, path, prototype, etc.)
  → Stage 2: LLM triage via Qwen3 Coder (OpenRouter) with fallback chain
  → Stage 3: Telegram alert with commit link, matched keywords, and LLM analysis
```

Commits that pass keyword filter but fail LLM triage are logged to `flagged.jsonl` for manual review. If all LLM providers fail, the alert is sent anyway — you never miss a potentially interesting commit.

## Features

- **60+ security keywords** covering command injection, auth, path traversal, prototype pollution, memory safety, crypto, DNS, and more
- **LLM fallback chain**: Qwen3 Coder 480B (OpenRouter) → Nemotron 3 Super (OpenRouter) → Llama 3.3 70B (Groq)
- **Zero cost**: all LLM providers are free tier
- **Telegram alerts** with commit link, matched keywords, and LLM summary
- **State tracking**: only processes new commits, persists across runs
- **Flagged log**: every flagged commit saved to `flagged.jsonl` for review

## Quick Start

### 1. Install

```bash
git clone https://github.com/YOUR_USERNAME/bugscope.git
cd bugscope
pip install requests
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` with your tokens:

| Variable | Required | Where to get it |
|---|---|---|
| `GITHUB_TOKEN` | Recommended | [github.com/settings/tokens](https://github.com/settings/tokens) (no scopes needed for public repos) |
| `TELEGRAM_BOT_TOKEN` | Yes | [@BotFather](https://t.me/BotFather) on Telegram |
| `TELEGRAM_CHAT_ID` | Yes | [@userinfobot](https://t.me/userinfobot) on Telegram |
| `OPENROUTER_API_KEY` | Yes | [openrouter.ai/keys](https://openrouter.ai/keys) (free, no credit card) |
| `GROQ_API_KEY` | Optional | [console.groq.com](https://console.groq.com) (free fallback) |

### 3. Test

```bash
python3 bugscope.py
```

### 4. Deploy

```bash
crontab -e
# Add:
*/30 * * * * cd /path/to/bugscope && python3 bugscope.py
```

## Configuration

### Target Repos

Edit the `TARGETS` list in `bugscope.py`:

```python
TARGETS = [
    # Add your targets here
]
```

### Keyword Sensitivity

Adjust `KEYWORD_THRESHOLD` (default: 2) — minimum keyword matches to flag a commit. Lower = more alerts, higher = less noise.

### LLM Toggle

Set `USE_LLM = False` to disable LLM analysis and rely only on keyword filtering.

## LLM Chain

BugScope tries each provider in order until one succeeds:

| Priority | Provider | Model | Cost |
|---|---|---|---|
| 1 | OpenRouter | `qwen/qwen3-coder:free` | Free (50 req/day) |
| 2 | OpenRouter | `nvidia/nemotron-3-super:free` | Free (50 req/day) |
| 3 | Groq | `llama-3.3-70b-versatile` | Free |

If all providers fail, the alert is sent anyway with an `llm-error` tag.

## Files

| File | Description |
|---|---|
| `bugscope.py` | Main script |
| `.env.example` | Template for `.env` |
| `state.json` | Tracks last seen commit per repo (auto-generated) |
| `flagged.jsonl` | Log of all flagged commits with analysis (auto-generated) |
| `bugscope.log` | Execution log |


