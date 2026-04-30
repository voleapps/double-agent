# DoubleAgent - A Coding Agent Guardrail, by [Vole Apps](https://voleapps.com)

A safety hook for autonomous coding agents. Sits between the agent and the tool
execution layer, so destructive operations get caught even when the agent has
talked itself past its system-prompt rules.

**v1 — works as a Claude Code PreToolUse hook. Other harnesses TODO.**

## What it does

When the agent tries to run a tool (Bash command, Edit, WebFetch, MCP tool,
etc.), this hook intercepts the call and runs it through a 3-layer pipeline:

1. **Hard-stop matcher** — regex denylist of operations no autonomous agent
   should ever perform (e.g., `rm -rf /`, `railway volume delete`, force-pushing
   to `main`). Matches → instant block, no LLM consulted.

2. **Soft matcher** — yellow-flag patterns that need contextual evaluation
   (anything containing "delete", curl-to-infrastructure-APIs, recursive rm,
   etc.). Matches → judge agent invoked.

3. **Judge agent** — small LLM (Haiku by default) evaluates the command against
   a narrow list of rules. Has *no* context about the agent's reasoning or
   accumulated session — by design, so it can't be talked into ALLOWing
   something the way the executing agent talked itself into doing it.

Blocks return a structured rejection message designed to discourage the agent
from looping through workarounds.

![image](https://voleapps.com/github/doubleagent-graph.webp)

## Why this matters

The PocketOS / Railway incident (April 2026) is the canonical motivation: a
Cursor agent running Claude Opus 4.6 deleted a production volume in 9 seconds
while explicitly violating four system-prompt rules it could later recite
verbatim. The rules were present, but were ignored regardless. This hook allows 
for unconditional rejection of certain operations, intelligent review of others, and moves the 
enforcement below the model layer where the model can't reason past it.

## Install

### Prerequisites

```bash
pip install pyyaml anthropic   # anthropic only needed if judge enabled
```

Python 3.9+.

### Set it up

1. Copy `guardrail.py` somewhere stable, e.g. `~/.claude/hooks/guardrail.py`,
   and make it executable:

   ```bash
   mkdir -p ~/.claude/hooks
   cp guardrail.py ~/.claude/hooks/guardrail.py
   chmod +x ~/.claude/hooks/guardrail.py
   ```

2. Copy the example config to one of these locations. The first file found
   wins — project-level overrides user-level overrides system-level:

   - `./.guardrail.yaml` (project-level, highest priority)
   - `~/.config/guardrail/config.yaml` (user-level)
   - `/etc/guardrail/config.yaml` (system-level fallback)

   If a config file exists but is malformed (YAML syntax error, etc.), the hook
   **fails closed**: every tool call is blocked with a clear error message until
   the config is fixed. A typo in YAML must never silently disable the safety
   layer. To return to "no rules" mode, delete the broken file — that is treated
   as the deliberate state of "no config installed" and falls open.

   ```bash
   mkdir -p ~/.config/guardrail
   cp config.example.yaml ~/.config/guardrail/config.yaml
   ```

3. If you want the judge enabled, set your Anthropic API key:

   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   ```

   And ensure `judge.enabled: true` in your config.

4. Wire it into Claude Code by adding to `~/.claude/settings.json`:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "*",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/hooks/guardrail.py"
             }
           ]
         }
       ]
     }
   }
   ```

   The `matcher: "*"` means it runs before every tool call. You can scope it
   to specific tools (e.g. `"Bash"`) if you only want shell commands checked.

## Test it before wiring it in

The script has a `--test` mode so you can verify rules work without involving
Claude Code at all:

```bash
# Should BLOCK (hard_stop)
python3 guardrail.py --test --tool Bash --command "railway volume delete xyz"

# Should BLOCK (hard_stop)
python3 guardrail.py --test --tool Bash --command "git push --force origin main"

# Should ALLOW
python3 guardrail.py --test --tool Bash --command "ls -la"

# Should escalate to judge (if enabled) - "delete" keyword
python3 guardrail.py --test --tool Bash --command "rm -rf /tmp/build-cache"

# Should BLOCK via soft_match - the curl-to-Railway-API case
python3 guardrail.py --test --tool Bash \
  --command 'curl -X POST https://api.railway.app/graphql -d "{\"query\":\"mutation { deleteVolume(id: 123) }\"}"'
```

You should see clear `ACTION: ALLOW` or `ACTION: BLOCK` output plus the
rejection message that would be shown to the agent.

## Configure your own rules

Edit `~/.config/guardrail/config.yaml`. Three sections:

- **`hard_stop`**: list of `{name, pattern, reason, applies_to?}`. Regex
  matched case-insensitive against the command. No override path. Use sparingly —
  these are operations you NEVER want.

- **`soft_match`**: same format. These trigger the judge.

- **`rules_for_judge`**: list of plain-language strings. The judge enforces
  these against any soft-matched command. Keep them narrow and unambiguous.

- **`applies_to`** (optional, on any rule): list of tool names the rule fires
  on, e.g. `applies_to: [Bash]`. Default (omitted) is "any tool". Only the
  *action-shaped* fields of each tool are scanned (Bash `command`, WebFetch
  `url`, Edit/Write `file_path`, etc.) — file content is intentionally NOT
  scanned, so a Write of a SQL migration containing `DROP DATABASE` will not
  trip a hard-stop. Scope rules explicitly when the pattern only makes sense
  for one tool.

- **`audit`**: optional block controlling the audit log:
  ```yaml
  audit:
    enabled: true
    max_size_mb: 10   # rotate at this size
    backup_count: 3   # keep audit.log.1 .. audit.log.N
  ```

- **`judge.timeout_seconds`**: cap on each judge API call (default 15s).
  Timeouts produce ESCALATE, which blocks — so the agent can't hang forever
  on a slow API.

A note on rule curation: the defaults are a starting point, not an exhaustive
list. As you use this in practice, expect to add rules specific to your
infrastructure (your DB names, your project names, your internal CLIs).

## What it doesn't catch (yet)

- **Compound shell commands**: things like `cd /prod && rm -rf .` — the regex
  matchers see the full command line, but if you only have `rm -rf` in your
  hard-stop, the `cd &&` prefix won't bypass it. However, if the agent writes
  a script and runs it via `bash script.sh`, the script contents aren't
  visible to the hook: only `file_path` is scanned for Write/Edit by default,
  not the file body. If you want script-content scanning, the per-tool field
  list is in [guardrail.py:TOOL_SEARCHABLE_FIELDS](guardrail.py) — extend it
  there and tag your rules with `applies_to: [Write, Edit]`.

- **HTTP-via-curl beyond the major providers**: the soft_match list covers
  Railway, Vercel, Fly, Heroku, DO, Linode. Add your own infrastructure
  hostnames as needed.

- **Indefinite agent suspension**: the hook can block, but it can't pause the
  agent loop and wait for a human approval that arrives 5 minutes later. For
  v1, blocking with a clear message and asking the user to act is the
  pattern. Real approval flows (Slack/webhook) are v2.

- **Anything not invoked through Claude Code's tool system**: the hook runs on
  tool calls only. If the agent finds a way to execute code outside that
  system (rare, but possible with some MCP servers), the hook won't see it.

## Debugging

The hook writes an audit log to `~/.guardrail/audit.log`:

```bash
tail -f ~/.guardrail/audit.log | jq .
```

Every decision (allow, block, escalate, judge call) is logged with metadata.
This is also useful for tuning rules — if you see things being escalated that
should clearly be allowed, the log tells you which rule fired.

The log rotates at `audit.max_size_mb` (default 10MB), keeping
`audit.backup_count` backups (default 3). Older rollovers are dropped.

Failure modes:

- **Malformed config file** → fail-CLOSED. Every tool call is blocked with a
  rejection message naming the broken file. Fix the YAML (or delete the file)
  to recover. A typo in your config must not silently disable protection.
- **No config file installed at any search path** → fail-OPEN with empty
  rule lists. The hook is a no-op. This is the deliberate "I haven't written
  rules yet" state.
- **Judge crash, API timeout, network error** → ESCALATE, which blocks. The
  agent gets a clear message, the user can retry or run manually.
- **Hook protocol parse error (malformed stdin from the harness)** → exits 0
  (allow). This is an upstream/Claude-Code-side issue, not a user
  misconfiguration, and a harness regression should not brick the agent.

## Layout

```
agent-guardrail/
├── guardrail.py            # the hook (single file)
├── config.example.yaml     # default rules + judge config
└── README.md               # this file
```

## License

Do whatever. This is meant to be hacked on.
