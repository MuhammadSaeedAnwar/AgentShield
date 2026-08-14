Thank you for contributing to AgentShield! To keep the project professional and easy to collaborate on, please follow these guidelines when contributing.

Getting started
- Fork the repository and open a branch named `feat/your-feature` or `fix/your-bug`.
- Run tests locally: from the repository root `python -m venv .venv && source .venv/bin/activate && pip install -e .` then `pytest -q`.
- Build the dataset: `python scripts/build_dataset.py` (this is fast and deterministic).

Code style
- Use clear, well‑documented Python. Type hints are encouraged; this project includes `py.typed`.
- Keep changes minimal and focused to make review easier. Add tests for new behavior where possible.

Pull requests
- Base your PR on the `main` branch. Provide a concise PR description and link to any related issue.
- If your change touches experiment results or dataset files, explain why and include a reproducible command to regenerate outputs.

Security and ethics
- This project is defensive research and uses a simulated, side-effect-free sandbox. Do not add or commit any real API keys or secrets.

Contact
- If you're not sure where to start, open an issue describing what you'd like to work on and tag it `good first issue`.
