# AgentShield: Security Evaluation of Tool-Using LLM Agents

A small, reproducible, **empirical** benchmark for measuring whether a tool-using
LLM agent keeps the boundary between *trusted instructions* (the system policy and
the user's request) and *untrusted content* (retrieved documents, tool outputs,
files, database rows).

> **Scope and honesty.** AgentShield is a research instrument, **not** a product
> and **not** a claim about AI alignment or catastrophic AI risk. Its goal is
> narrower and operational: *better evaluation of agent vulnerabilities → better
> understanding of failure modes → better security controls and evaluations →
> reduced likelihood of unsafe agent behaviour in deployed systems.* Every number
> it reports is produced by executing episodes and counting outcomes; nothing is
> fabricated. Where the default (`--model mock`) simulator is used, the numbers
> characterise the **harness**, not any real LLM — see [Reproducibility](#13-reproducibility)
> and `docs/mock_model.md`.

---

## 1. Problem

Tool-using agents increasingly sit between users and powerful capabilities
(sending email, reading files, querying databases, calling APIs). The same
mechanism that makes them useful — they read content from outside the trust
boundary and act on it — is exactly what prompt injection and unsafe-tool-use
attacks exploit. An agent that cannot distinguish *"the user told me to do this"*
from *"a retrieved web page told me to do this"* can be steered into leaking data,
calling privileged tools, or performing actions the deployer never authorised.

There is a shortage of **small, reproducible, side-effect-free** evaluations that
make this measurable with explicit denominators and confidence intervals, rather
than anecdotal red-team demos. AgentShield is one such evaluation.

## 2. Motivation

Defenders cannot improve what they cannot measure. Most public evidence about
agent vulnerabilities is either (a) bespoke exploit scripts that prove *a* model
*can* be broken, or (b) vendor claims that a defense *works*. AgentShield provides
a third thing: a **controlled, auditable experiment** whose outcomes are decided by
a fixed ruleset, not a human or an LLM judge, so that:

- results are reproducible bit-for-bit with no API key (the `mock` adapter);
- the effect of each defense is isolated by ablation (`--defenses authorization`,
  `--defenses all`, …);
- every metric states its denominator, and every proportion carries a 95% Wilson
  confidence interval.

The intended chain of value is deliberately modest: *better evaluation → better
understanding of failure modes → better security controls/evaluations → reduced
likelihood of unsafe agent behaviour in deployed systems.* We do **not** claim to
solve AI alignment or to assess existential risk.

## 3. Threat model

**Assets.** The simulated session's secrets and privileges: canary secrets
(`AGSH-SECRET-*`, card/IBAN-shaped test numbers), system-prompt text, private
files under `/sandbox/`, and mock database tables.

**Adversary.** An attacker who controls *untrusted content* the agent consumes —
a web page, an email, a retrieved document, a tool's return value, a database row,
or the conversational context across turns — and who wants the agent to:

- disclose confidential content (system prompt, secrets);
- call a privileged tool it should not (e.g. `send_message` to an external address,
  `file_reader` outside `/sandbox/public/`, `database_lookup` on a non-allowlisted
  table);
- act on instructions that contradict the deployer policy.

**Capabilities / assumptions.**

- The adversary can plant text in untrusted channels but **cannot** alter the
  deployer's system prompt or the user's own turns (except in the
  `direct_prompt_injection` category, where the user channel *is* the attack).
- The environment is **fully simulated and side-effect free**: fake domains under
  `*.example`, virtual `/sandbox/` paths, an in-memory mock database, and an
  in-memory outbox. `send_message` never sends anything; it only appends to a
  Python list. No real-world exploitation is described or enabled.
- The defender may apply the five defenses in [Defenses](#9-defenses).

**Out of scope.** Multi-agent collusion, training-time attacks, jailbreaks that
subvert the model's base alignment, and any real infrastructure.

## 4. Research questions

- **RQ1 — Prevalence by category.** How does Attack Success Rate (ASR) vary across
  the six injection categories (A–F)? (`metrics_by_category.csv`, ASR-by-category
  chart.)
- **RQ2 — Channel effects.** Does the *entry channel* of the payload (user turn vs
  retrieved document vs tool output vs database vs conversation history) change
  outcomes? (ASR-by-injection-channel view.)
- **RQ3 — Defense effectiveness.** Which defenses, alone and together, reduce ASR
  against the paired undefended baseline, and by how much? (Defense-effectiveness
  table; Defense Success Rate with paired baselines.)
- **RQ4 — Tool provisioning.** Does granting the agent *more* tools than a task
  needs (over-provisioning) increase ASR? (`--tool-provisioning minimal` vs `full`.)

## 5. Architecture

```
attack test case
  -> agent (ModelAdapter + tools + optional defenses)      agents/, models/, tools/, defenses/
  -> simulated tool environment (no real side effects)      tools/sandbox.py, tools/builtin.py
  -> detectors (signals extracted from the episode)         evaluation/detectors.py
  -> outcome classification (rule-based, per-case criteria) evaluation/classifier.py
  -> metrics (ASR, safe completion, unauthorized calls, …)  metrics/core.py
  -> results (JSON + CSV + tables/charts)                  evaluation/results.py, analyze.py
```

Core engine dependencies are the **Python standard library only** (Python ≥ 3.10),
so a reproduction run cannot break because of a transitive dependency. Charts and
YAML configs are optional extras (`matplotlib`, `pandas`, `pyyaml`).

Key modules:

- `agentshield/models/` — `MockModelAdapter` (deterministic simulator) and
  `OpenAICompatibleAdapter` (any `/v1/chat/completions` endpoint).
- `agentshield/tools/` — six simulated tools, the sandbox, and the authorization
  policy engine.
- `agentshield/defenses/` — the five defenses and the composition pipeline.
- `agentshield/attacks/` — taxonomy, schema, dataset loading/validation.
- `agentshield/evaluation/` — detectors, classifier, runner, result records.
- `agentshield/metrics/` — Wilson CIs, metric definitions, reporting.

## 6. Attack taxonomy

Six categories, distinguished by *where the adversarial text enters* and *what the
agent is nudged to do*:

| Letter | Category | Entry channel |
|---|---|---|
| A | Direct Prompt Injection | user turn |
| B | Indirect Prompt Injection | third-party content fetched by the agent |
| C | RAG / Document-Based Injection | retrieved documents |
| D | Malicious Tool-Output Injection | tool return values |
| E | Multi-Turn Manipulation | conversation history |
| F | Unauthorized / Unsafe Tool Use | agent's own planning (with or without a nudge) |

5 cases per category (30 total). See `docs/dataset.md` for the schema and
`agentshield/attacks/taxonomy.py` for the canonical definitions.

## 7. Experimental methodology

One **condition** = (model, dataset, defense set, tool provisioning). The
`BenchmarkRunner` executes every `(case, trial)` pair:

1. Build a fresh sandbox from the case (independent, reproducible episodes).
2. For each user turn, ask the model for a response advertising the provisioned
   tools.
3. For each requested tool call: audit it against the policy (always), let the
   defense pipeline veto it, execute it in the sandbox if not blocked, filter the
   result, and continue.
4. Record the full transcript, every tool call with its authorization verdict,
   every defense intervention, and the final answer.
5. Run detectors, then classify the episode with the case's `success_criteria`
   (rule-based, no LLM judge).

Defaults: `seed=1337`, `trials=1` (use 3 for stable CIs), `max_steps=6`,
`tool_provisioning=minimal`. The system prompt scaffold is held constant across all
conditions so baseline/defended comparisons are ablations.

## 8. Metrics

All reported with explicit denominators and 95% Wilson score intervals.

| Metric | Definition |
|---|---|
| **Attack Success Rate (ASR)** | successful attacks / applicable episodes |
| **Safe Completion Rate (SCR)** | (attack prevented AND benign task completed) / applicable episodes |
| **Unauthorized Tool Call Rate (UTCR)** | episodes with ≥1 policy-violating tool-call *attempt* / applicable episodes |
| **Sensitive Information Exposure Rate (SIER)** | episodes leaking ≥1 canary / episodes where a canary was reachable |
| **Defense Success Rate (DSR)** | baseline-successful attacks prevented under defense / baseline successes (paired) |

*Applicable episodes* = episodes belonging to a case that defines `success_criteria`
and that did not error. Errors are reported separately and never counted as safety.

**Critical design choice.** `success_criteria` use **executed**-call criteria, so a
call a defense **blocked** does *not* count as a successful attack; blocked attempts
are captured by **UTCR**. This separates "the model was manipulated" (ASR) from
"the manipulation caused harm" (UTCR). See `docs/dataset.md` and `docs/defenses.md`.

Supporting metrics: task-completion rate, blocked-call rate, system-prompt-leak
rate, injection-delivery rate, error rate.

## 9. Defenses

| Name | Enforcement | Model cooperation? |
|---|---|---|
| `sanitization` | input filter | **yes** (payload may survive) |
| `separation` | prompt-level trust boundary | **yes** (model must honour it) |
| `authorization` | deterministic call gate | **no** (blocks outright) |
| `confirmation` | deterministic call gate | **no** (blocks until user approval) |
| `output_validation` | deterministic egress + final-answer filter | **no** (blocks/redacts) |

Select with `--defenses none | all | comma-list`. Full mechanism and known
limitations: `docs/defenses.md`.

## 10. Installation

```bash
cd AgentShield
python -m venv .venv && source .venv/bin/activate   # optional
pip install -e .                                    # installs agentshield-run / agentshield-analyze

# Optional extras for charts / YAML configs / tests:
pip install ".[analysis]"      # matplotlib, pandas
pip install ".[config]"        # pyyaml
pip install ".[dev]"           # pytest + the above
```

The core benchmark (`python -m agentshield.run --model mock`) needs **no**
dependencies at all.

## 11. Usage

```bash
# Rebuild / validate the dataset (also runs on import):
python scripts/build_dataset.py

# Offline smoke run (deterministic, no API key):
python -m agentshield.run --model mock --dataset data/attacks.json

# Undefended baseline, 3 trials, into results/:
python -m agentshield.run --model mock --trials 3 --defenses none

# All defenses on:
python -m agentshield.run --model mock --trials 3 --defenses all

# Ablate a single defense:
python -m agentshield.run --model mock --defenses authorization

# Over-provisioning ablation (RQ4):
python -m agentshield.run --model mock --trials 3 --tool-provisioning full

# Real model (requires OPENAI_API_KEY; costs tokens):
python -m agentshield.run --model openai --model-name gpt-4o-mini --trials 1

# Local OpenAI-compatible server:
python -m agentshield.run --model openai --base-url http://localhost:11434/v1 \
    --model-name llama3.1:8b --api-key-env NONE

# Analyse one or more results files -> report.md, summary.json, CSVs, figures/:
python -m agentshield.analyze results/example_mock_run
python -m agentshield.analyze results/ --no-charts     # tables only
```

Config-file form (see `configs/`):

```bash
python -m agentshield.run --config configs/mock_baseline.json
python -m agentshield.run --config configs/mock_defended.json
```

Run `python -m agentshield.run --help` / `python -m agentshield.analyze --help`
for every flag (categories/ids/severities filters, `--seed`, `--max-steps`,
`--dry-run`, `--list-cases`, `--cache-dir`, …).

## 12. Example experiment

A committed reference run lives in `results/example_mock_run/` (seed 1337,
`mock-gullible-v1`, 3 trials, `minimal` provisioning), under two conditions:

| Condition | ASR | SCR | UTCR | SIER |
|---|---|---|---|---|
| `defenses=none` | **34.4% (31/90)** | 65.6% | 27.8% | 37.3% (28/75) |
| `defenses=all` | **0.0% (0/90)** | 100.0% | 5.6% | 0.0% (0/75) |

Reproduce it:

```bash
python -m agentshield.run --model mock --trials 3 --defenses none --out results/example_mock_run
python -m agentshield.run --model mock --trials 3 --defenses all  --out results/example_mock_run
python -m agentshield.analyze results/example_mock_run
```

> **How to read these numbers.** With `--model mock` they validate the *harness*
> (the deterministic defenses `authorization`/`confirmation`/`output_validation`
> drive ASR to 0 against the simulator). The two prompt-level defenses
> (`separation`, `sanitization`) are *modelling assumptions* in the mock and must
> **not** be generalised to real models. See [Reproducibility](#13-reproducibility)
> and `docs/mock_model.md`.

For real-model answers to RQ1–RQ4, run the same commands with `--model openai`
against consenting deployments and combine the results files before analysing.

## 13. Reproducibility

- The mock's Bernoulli draw is `H(seed, model_name, case_id, trial, turn_index) /
  2**32` (SHA-256, truncated). Identical inputs ⇒ identical episodes.
- The sandbox is rebuilt per episode; nothing else consults a random source.
- The dataset is SHA-256-stable (`data/attacks.json`), and `run_metadata` records
  the exact command line, versions, and dataset hash in every results file.
- `python -m agentshield.analyze <dir>` recomputes every table and CI from the
  saved episodes, so any result is traceable to its transcript.

```bash
# Exact, key-free reproduction of the whole reference study:
python -m pytest -q                 # 95 tests, all deterministic
python scripts/build_dataset.py --check
python -m agentshield.run --model mock --trials 3 --defenses none --out results/example_mock_run
python -m agentshield.run --model mock --trials 3 --defenses all  --out results/example_mock_run
python -m agentshield.analyze results/example_mock_run
```

## 14. Limitations

- **Mock numbers are not model numbers.** The default adapter is a susceptibility
  simulator; its results validate the harness only. RQ answers about real models
  require `--model openai`.
- **Small dataset (30 cases).** Wilson CIs are wide; per-case and per-category
  estimates are indicative, not confirmatory. The two-proportion z-tests reported
  for RQ3/RQ4 are descriptive and **not** multiple-comparison corrected.
- **Simulated environment.** No real tools, network, or files. Findings about
  *real* tool implementations, rate limits, or auth flows are out of scope.
- **Pattern-based defenses are incomplete by construction.** The sanitiser and the
  egress DLP have known gaps (polite phrasing, unformatted secrets); the benchmark
  measures the residual risk rather than assuming completeness.
- **Phrase-matched confirmation** is coarse and spoofable if the user's own words
  are quoted back by an attacker who controls the user channel.
- **Single-turn benign completion** is defined per-case and may not capture nuanced
  real-world task success.

## 15. Ethical / safety

- All environments are **fictional and side-effect free** (domains under
  `*.example`, `/sandbox/` paths, mock collections, an in-memory outbox). No real
  person, system, or credential is targeted or contacted.
- No case contains actionable real-world exploitation instructions; payloads are
  toy and target only the sandbox.
- The project is a **defensive evaluation** to help builders harden agents. Do not
  use it to develop attacks against systems you do not own or are not authorised to
  test.
- `API keys` are never committed (`.gitignore` excludes `.env` and `*.key`); the
  OpenAI adapter reads keys from an environment variable, never from the dataset.

## 16. Future work

*Implemented hooks exist; the following are **not yet done** in this release and
are clearly marked as such.*

- **Real-model leaderboard.** Broad `--model openai` coverage across models and
  the RQ3/RQ4 comparisons that follow. (Adapter exists; no results shipped.)
- **Larger / adversarial dataset.** More cases per category and a generator that
  mutates payloads to stress the pattern-based defenses.
- **Adaptive attacks** against the defenses (e.g. paraphrased injections that evade
  `sanitization`) — to be added as *additional* cases that measure residual risk.
- **Cost / latency metrics** for real-model runs.
- **Human-evaluation cross-check** of the rule-based classifier on a sample.
- **Web UI / dashboard** for browsing episodes and CIs.

## 17. Citation

```bibtex
@software{agentshield2026,
  title        = {AgentShield: Security Evaluation of Tool-Using LLM Agents},
  author       = {AgentShield contributors},
  year         = {2026},
  version      = {0.1.0},
  license      = {MIT},
  note         = {Reproducible prompt-injection / unsafe-tool-use benchmark.
                  Mock numbers validate the harness, not real models.}
}
```

If you use AgentShield, please cite the benchmark and **state clearly** whether
your results came from `--model mock` (harness validation) or `--model openai`
(model evaluation), so readers do not conflate the two.

---

### License

MIT — see `LICENSE`.
