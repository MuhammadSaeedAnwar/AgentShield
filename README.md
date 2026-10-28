# AgentShield

A compact benchmark for evaluating whether tool-using agents keep a trusted instruction boundary.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m agentshield.run --model mock --dataset data/attacks.json
```

This repo is intentionally reproducible: the mock adapter runs offline without an API key and the harness records exact conditions for later analysis.
