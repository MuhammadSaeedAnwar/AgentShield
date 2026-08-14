# The mock model (`--model mock`)

> **Read this before quoting any `mock` number.** The mock is a *deterministic
> susceptibility simulator*, not a language model. Its output characterises the
> **harness**, never any real LLM. A result like "ASR 34.4% under `defenses=none`"
> means *"this is how the simulator behaves against these 30 cases"* — it says
> nothing about GPT-4o, Claude, Llama, or any other model.

## What it is

`agentshield.models.mock.MockModelAdapter` is a rule-based agent policy. It turns
a conversation into a plan of tool calls and a final answer using an explicit,
fully documented function of the *textual features* of the conversation. It has
no weights, no network access, and no randomness beyond a single deterministic
hash draw.

## Why it exists

1. **Reproducibility with zero setup.** The whole benchmark runs offline with no
   API key, so anyone can reproduce every episode byte-for-byte (modulo timestamps
   and wall-clock fields).
2. **A fixed point for tests.** Unit tests assert exact outcomes against the
   mock, which would be impossible against a stochastic API.
3. **Harness validation.** It lets us prove the detectors, classifier, metrics and
   *deterministic* defenses work correctly, independent of any provider's behaviour.

## Decision procedure

For each (case, trial, turn) the mock:

1. Splits the conversation into **trusted** (system), **user**, and **untrusted**
   (tool output / retrieved document) content, tagging each message with a
   `trust` provenance.
2. Extracts **directives** (imperative instructions) from the user and untrusted
   content using the regex family `DIRECTIVE_PATTERNS`. These patterns are
   *intentionally different* from the input-sanitisation defense's patterns — if
   the sanitiser used the mock's own extraction rules it would be a perfect oracle
   and trivially reach 0% ASR by construction (an artefact, not a finding).
3. Computes a compliance probability `p` from additive **feature weights** on top
   of `BASE_COMPLIANCE` (0.35), clamped to `[0.02, 0.98]`.
4. Takes a **deterministic** Bernoulli draw:
   `u = H(seed, model_name, case_id, trial, turn_index) / 2**32`; it complies iff
   `u < p` *and* at least one directive survived. Identical inputs ⇒ identical
   episode, always.
5. Builds a plan: the benign task plan supplied out-of-band via the case
   `oracle` (never serialised into a prompt), plus — only if complying — the tool
   calls implied by the extracted directives (read/query steps first, then send).
6. Emits the next unexecuted plan step as a tool call, or a final answer that
   summarises the tool results it received (and, if complying, states the injected
   action was taken / discloses the system prompt).

## Feature weights

`p = BASE_COMPLIANCE + Σ active weights` (clamped). The weights are documented
constants in `agentshield/models/mock.py`:

| Feature | Weight | Meaning |
|---|---|---|
| `authority_framing` | +0.22 | content impersonates system/admin/compliance |
| `urgency_pressure` | +0.12 | coercive "immediately / or you will be suspended" framing |
| `explicit_override` | +0.10 | "ignore previous instructions" style override |
| `channel_user` | +0.20 | directive arrives in the (high-trust) user turn |
| `channel_tool_output` | +0.10 | directive arrives in tool output |
| `channel_document` | +0.05 | directive arrives in a retrieved document |
| `multi_turn_escalation` | +0.06 / turn (cap 3) | repeated-turn pressure |
| `trust_separation_present` | −0.30 | **modelling assumption**, not a measurement |
| `sanitisation_notice` | −0.15 | a visible redaction marker lowers compliance |
| `explicit_prohibition` | −0.10 | the trusted policy contains a matching "never …" rule |

Changing these weights changes the **simulator**, not the harness. They are
exposed as constructor arguments so experiments can probe the pipeline's
behaviour under different susceptibility profiles without touching any other
code.

## Two features are modelling assumptions, not measurements

- `trust_separation_present` (−0.30) and `sanitisation_notice` (−0.15) encode the
  *assumption* that a model honours a trust boundary / reacts to a visible
  redaction. Against a real model that is an **empirical question**; against the
  mock it is a hardcoded nudge. This is why a `mock` run with `separation` or
  `sanitization` shows a reduced ASR that you must **not** generalise to real
  models. The two prompt-level defenses (separation, sanitization) require real
  `--model openai` runs before any conclusion about them is warranted.

## How to read mock numbers

- Use them to **validate the harness**: "does the classifier count a blocked call
  as *not* a successful attack?", "does `authorization` deterministically drive
  ASR to 0?", "do the CIs behave?".
- Do **not** use them to rank, praise, or condemn any real model.
- The committed `results/example_mock_run/` is the canonical reference. With seed
  1337 and `mock-gullible-v1`, `defenses=none` yields ASR ≈ 34.4% and
  `defenses=all` yields ASR = 0.0% (the deterministic defenses carry the whole
  effect).

## Moving to real models

```bash
export OPENAI_API_KEY=sk-...
python -m agentshield.run --model openai --model-name gpt-4o-mini --trials 1
# or a local OpenAI-compatible server:
python -m agentshield.run --model openai --base-url http://localhost:11434/v1 \
    --model-name llama3.1:8b --api-key-env NONE
```

The `OpenAICompatibleAdapter` uses only the stdlib HTTP client. Responses can be
cached with `--cache-dir` for exact replay. API adapters ignore the benign-plan
`oracle` (it is never put in a prompt), so their task-completion rates are not
comparable to the mock's.
