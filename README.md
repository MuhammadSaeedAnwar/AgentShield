AgentShield

Note: This repository currently contains two parallel layouts for the agentshield package:

1) Legacy nested layout (canonical source location):
   - AgentShield/AgentShield/agentshield/
   - This is the original, full source tree (tests, configs, data, results, etc.).

2) Top-level placeholder layout (this branch `fix/flatten-structure`):
   - agentshield/  (lightweight placeholders intended as a temporary compatibility layer)

Why the placeholders exist
- Some tools, CI systems, or contributors expect to import the package from a top-level module (import agentshield). To avoid immediate breakage while planning an atomic migration, this branch adds placeholders that point at the original sources.

If you landed here (contributor guidance)
- To run tests against the canonical source without changing the repo layout:
  - cd to the repo root and run:
    - python -m venv .venv && source .venv/bin/activate
    - pip install -r AgentShield/AgentShield/requirements.txt
    - PYTHONPATH=AgentShield/AgentShield pytest -q

- To test using the flattened top-level package (work in progress):
  - Checkout branch: git checkout fix/flatten-structure
  - Copy the real package into the top-level place (optional):
    - rsync -av --exclude='__pycache__' AgentShield/AgentShield/agentshield/ agentshield/
    - pip install -e .
    - pytest -q

Branch status
- Branch: fix/flatten-structure
- Commit: placeholder files added to create a top-level agentshield/ layout. The original source tree remains under AgentShield/AgentShield/. This branch is intended to be the staging area for a tidy migration if you choose to proceed.

If you want me to finish the migration
- Reply with one of: "copy real files", "open PR", "revert branch" or "leave as-is" and I will perform that action.