# 🔎 Autonomous SOC Analyst — Technical Report

## 1. Executive Summary

Autonomous SOC Analyst is a command-line tool that runs a two-stage LLM pipeline against real Microsoft security telemetry: an OpenAI model first decides *what* to query (which Log Analytics table, which device, which time range) via real function calling, a KQL query built from those parameters runs against a real Azure Log Analytics workspace, and a second OpenAI call reasons over the returned log rows to produce structured, MITRE ATT&CK-mapped findings.

**Target user:** a SOC analyst who wants a natural-language front end over Microsoft Defender for Endpoint (MDE) and Azure AD log tables — "find anything suspicious on this device in the last 3 hours" instead of hand-writing KQL.

**Key differentiator from ControlLayer (the other project in this portfolio):** this one *does* give the model tools and lets it choose how to use them. ControlLayer's AI Assistant deliberately never passes a `tools` parameter to the model — this project is the counterexample, showing real OpenAI function-calling used to let an LLM select query parameters before a human-reviewed second pass reasons over the results. The two projects together demonstrate both sides of the same judgment call: knowing when tool use is warranted and when it isn't.

**Current state:** a working CLI script, tested against a real Azure Log Analytics workspace across the full MITRE ATT&CK lifecycle (documented with screenshots in the README, recon through impact). Not a service — no auth, no API surface, no tests. That's an accurate description, not a criticism; it's a focused proof-of-concept for a specific reasoning pattern, not a product.

---

## 2. Problem Statement

SOC analysts spend a lot of triage time translating an investigative question ("did anything weird happen on this box recently?") into the right KQL query against the right table, then re-reading raw rows for anything that maps to a known attacker technique. That translation step — natural language to query, and log rows to MITRE-mapped findings — is repetitive and is exactly the kind of pattern-matching an LLM is well suited to accelerate, provided a human still reviews the output before acting on it.

**Why generic chat-with-your-logs tools aren't enough:** without a defined tool contract, a model either has to guess at query syntax itself (error-prone) or a human still has to write the KQL by hand before the model can help at all. This project's answer is a fixed function contract — the model requests parameters, deterministic code builds the actual query — so the model never writes or executes a query directly.

---

## 3. How It Works, End to End

1. The analyst types a request in plain language (e.g., *"Get all processes from computer 'windows-target-1' over the last 3 hours and check if any look suspicious."*).
2. **Stage 1 — parameter selection (real tool calling):** `protocols/tool_routing.get_log_query_from_agent` sends that request to GPT-4.1 with a single tool, `query_log_analytics_individual_device`, and `tool_choice="auto"`. The model returns structured arguments: `table_name`, `device_name` or `caller`, `time_range_hours`, `fields`. The model never sees or touches the actual Azure workspace — it only chooses arguments for code to use.
3. **Query construction and execution:** `queries/log_analytics_queries.query_devicelogonevents` builds a KQL string from those arguments (a different `where` clause depending on which table was chosen) and runs it against a real workspace via `azure.monitor.query.LogsQueryClient`, authenticated with `DefaultAzureCredential`. Results come back as a pandas DataFrame, serialized to CSV.
4. **Stage 2 — threat hunting over real data:** `context.prompt_builder.build_threat_hunt_prompt` combines the original request, a table-specific system prompt (one of ten, tailored per log table — `context/prompts.py`), formatting instructions, and the actual CSV log data into a single user message. `protocols.hunt_protocol.hunt` sends that to GPT-4.1 and parses the response as a JSON array of findings.
5. **Output:** `utilities.display_threats` prints each finding to the console (title, description, MITRE tactic/technique/sub-technique, confidence, log lines, IOCs, tags, recommendations, notes) and appends every finding to a local `threats.jsonl` file.

---

## 4. Agentic AI Design

- **Two separate LLM calls, two separate jobs.** The parameter-selection call and the reasoning call use different system prompts and different scopes — the first is only allowed to pick query arguments, the second only reasons over data it's handed. Neither call can trigger the other's action directly.
- **Real function calling, narrowly scoped.** One tool is registered (`query_log_analytics_individual_device`), with a required-parameters list and an explicit table-and-field vocabulary in its description. The model chooses arguments; it does not execute the query — `queries/log_analytics_queries.py` does, in application code, after the model's turn ends.
- **Ten table-specific system prompts** (`context/prompts.py`), each scoped to the actual fields and attack patterns relevant to that log source (e.g., `DeviceRegistryEvents`' prompt is about persistence/defense-evasion registry keys; `SigninLogs`' prompt is about impossible travel and password spray). This is meaningfully more specific than one generic "find bad stuff" prompt, and it's a good example of prompt engineering tailored to the data shape rather than the task in the abstract.
- **Structured output contract.** The hunt stage is instructed to return only a JSON array matching a fixed schema (title, description, MITRE mapping, log lines, confidence, recommendations, IOCs, tags, notes) — machine-parseable, and durable via the `threats.jsonl` append.
- **Human-in-the-loop:** findings are displayed for a person to read; nothing in the tool takes a remediation action or writes back to Azure. The tool answers "what happened," it doesn't decide "what to do about it."

---

## 5. MITRE ATT&CK Coverage

The README documents a full walkthrough across the ATT&CK lifecycle — Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, and Impact — with actual tool output captured at each stage. That's the strongest evidence in this project: not a claim that it maps to MITRE, but a documented run showing it doing so across the entire attack chain in what appears to be a lab/range environment.

---

## 6. Security & Risk Considerations

Written the same way as ControlLayer's security section: what's solid, and what's an open gap, without softening either.

**Real gap — KQL injection.** `queries/log_analytics_queries.py` builds KQL via raw f-string interpolation of `device_name` and `caller` (e.g. `where DeviceName startswith "{device_name}"`), and those values originate from the model's tool-call arguments, which in turn come from user free text. There's no escaping or parameterization. A crafted device name containing a `"` followed by additional KQL clauses could alter the query's meaning — the same class of bug as SQL injection, applied to KQL. This is the single most important thing to fix before this pattern is reused anywhere with untrusted input.

**Real gap — brittle response parsing.** `protocols/hunt_protocol.hunt` parses the model's response with `.replace("\n","").replace("'","").replace("`","").replace("json","")` before `json.loads()`. This is defending against the model wrapping JSON in a Markdown code fence, but it does so by blindly stripping every single quote and backtick from the entire response — which would also corrupt a legitimate apostrophe or backtick inside a finding's own description text — and there's no `try/except` around the parse, so a response that isn't valid JSON after this cleanup crashes the run. Using the OpenAI SDK's JSON response-format mode (or a Pydantic-validated structured output) instead of manual string surgery would fix both problems at once.

**Real gap — dead, duplicated code in `utilities.py`.** That file contains a second, unused copy of the tool definition and three unused draft system prompts (`system_prompt`, `threat_hunt_system_prompt`, `log_analysis_prompt`) — leftovers from an earlier iteration that `main.py` never imports. It also imports `requests`, which is never used. Worth cleaning up; it's not a security issue, but it's exactly the kind of unused-code question a reviewer would ask about.

**Handled reasonably well — secrets.** `LOG_ANALYTICS_WORKSPACE_ID` and `API_KEY` are imported from a local `secrets_` module that was never committed to git history (confirmed by checking `git log --all` for that filename) — the credential path is kept out of source control, even without an explicit `.gitignore` entry for it.

**Not addressed — no error handling around either external call.** If the model doesn't return a tool call, or the Azure query fails, or the JSON parse fails, the script raises an uncaught exception. Acceptable for a CLI proof of concept; would need real error handling before this became anything more than that.

---

## 7. Limitations & Risks

1. KQL injection via unescaped `device_name`/`caller` interpolation (Section 6) — the top item to fix.
2. Brittle JSON extraction with no error handling on a failed parse.
3. `utilities.py` carries dead, duplicated tool/prompt definitions from an earlier version.
4. No `requirements.txt` — dependencies (`openai`, `azure-identity`, `azure-monitor-query`, `colorama`, `pandas`) have to be inferred from imports.
5. No automated tests.
6. Single-table tool contract — `query_log_analytics_individual_device` handles one query shape per call; a real investigation that needs to correlate across multiple tables in one pass would need multiple round trips.

---

## 8. Future Enhancements

1. Parameterize the KQL builder instead of string-interpolating user/model-derived values.
2. Replace manual string stripping before `json.loads()` with the OpenAI SDK's structured output / JSON mode, with a real `try/except` around the parse.
3. Delete the unused tool/prompt definitions in `utilities.py`.
4. Add a `requirements.txt` (or `pyproject.toml`) pinning actual dependency versions.
5. Add unit tests around the KQL builder and the response parser specifically — the two riskiest pieces of logic.
6. Allow the model to request more than one table per investigation, so a single hunt can correlate across, say, `DeviceLogonEvents` and `SigninLogs` without a separate manual run.

---

## 9. Quick Start

1. Install dependencies (no `requirements.txt` yet — install directly): `pip install openai azure-identity azure-monitor-query colorama pandas`.
2. Create a local `secrets_.py` with `LOG_ANALYTICS_WORKSPACE_ID` and `API_KEY` (OpenAI key) — this file is intentionally not in the repo.
3. Authenticate to Azure however `DefaultAzureCredential` expects in your environment (e.g., `az login`, or the standard environment variables).
4. Run `python main.py`, and describe what you want to investigate when prompted.
5. Review the console output; every finding is also appended to `threats.jsonl` in the working directory.

---

## 10. Conclusion

This project's value for an interview is specific: it's proof of hands-on, working OpenAI function-calling against a real Microsoft security data source, with the reasoning step kept separate from the tool-selection step and a human reading every output before acting. Paired with ControlLayer — which makes the opposite, equally deliberate choice to give its AI assistant no tools at all — the two projects together show the same engineer making the call both ways, for reasons that map to what each system actually needed. The KQL-injection gap and the brittle JSON parsing are real, findable issues in the current code, and knowing exactly where they are and how to fix them is a better answer in an interview than not having looked.
