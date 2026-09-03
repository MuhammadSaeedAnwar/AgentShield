CLEANUP and next steps

This branch creates a top-level agentshield/ layout containing lightweight placeholder modules that point to the original full sources in AgentShield/AgentShield/. The intent is to keep the repo functional for tools and CI that expect a top-level package while preserving the original sources until a careful, atomic migration is performed.

What these placeholders are
- A small set of stub files placed under agentshield/ (package modules and subpackages).
- Copied metadata/config stubs (pyproject.toml, requirements.txt, README.md, configs/, data/, results/ placeholders).

Why this is temporary
- Placeholders avoid breaking the repository but duplicate structure which can be confusing. The real implementation remains under AgentShield/AgentShield/agentshield/.

Recommended cleanup plan (safe, step-by-step)
1. Review and agree the final layout: keep nested tree or adopt top-level agentshield/ as canonical.

2. If adopting top-level agentshield/:
   a. On the branch fix/flatten-structure, copy the real package files from AgentShield/AgentShield/agentshield/ into agentshield/ (overwrite placeholders):
      - Example:
        mkdir -p agentshield
        rsync -av --exclude='__pycache__' AgentShield/AgentShield/agentshield/ agentshield/

   b. Run tests locally and in CI. Example commands:
      - python -m venv .venv && source .venv/bin/activate
      - pip install -r AgentShield/AgentShield/requirements.txt
      - PYTHONPATH=. pytest -q
      - Or: pip install -e . && pytest

   c. Update packaging metadata (pyproject.toml) to point at the correct package name/module if required.

   d. Remove the legacy nested tree or keep it as an archived directory ("legacy/AgentShield-src/") to avoid accidental divergence. If removing, do it in the same branch commit so history shows a single atomic move.

   e. Open a PR from fix/flatten-structure and request reviewers run the test matrix.

3. If keeping the nested layout:
   a. Revert the flatten commit (this branch) and leave the repo untouched.

Notes
- I intentionally left the original sources untouched under AgentShield/AgentShield/ so there is no immediate loss of code.
- I can automate the rsync/copy step and run tests within the CI (where available), then create a PR. I cannot open the PR automatically from here unless you ask me to — instead I will prepare the branch (already done) and push commits.

Next actions I can take for you now
- Copy the real files from AgentShield/AgentShield/agentshield/ into agentshield/ (overwrite placeholders) and run a quick test command in CI or locally.
- Prepare a PR description file (PULL_REQUEST.md) summarising the change.
- Revert this branch (if you change your mind).

Tell me which of the above you want me to perform next.