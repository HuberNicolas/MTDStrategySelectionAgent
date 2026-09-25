# TODO

Open tasks around making the repository public. See also [Known issues](README.md#known-issues).

## 1. Tooling and cleanup

- [x] Add a `pyproject.toml` and `uv.lock` reproducing the 2022 dependency versions
- [x] Configure and apply Ruff (import sorting, formatting, error checks)
- [x] Mark intentional catch-all excepts with justified `# noqa` comments
- [x] Expand `.gitignore` (runtime logs, caches, editor/OS files)

## 2. Documentation

- [x] Rewrite the README (overview, architecture, quick start, strategies, data)
- [x] Add `docs/` (architecture, policy, evaluation)
- [x] Add an MIT `LICENSE`

## 3. Code quality (optional, out of scope for a faithful archive)

- [ ] Make the hard-coded paths (`/root/MTDStrategySelectionAgent`, `/root/sample-data`, `/root/Malware`) configurable
- [ ] Fix the Python 3.12+ regex `SyntaxWarning`s (raw strings) if the code should run on modern Python
- [ ] Add the undeclared `argparse`/stdlib assumptions to the docs where scripts expect a specific OS layout

## 4. Before publishing

- [x] Choose and add a license (MIT)
- [x] Add the project context (thesis, institution, supervisors) to the README
- [x] Credit third parties (MTD Framework by Jordan Cedeño)
- [x] Unify the git author/committer email in history to `nicolas.huber.dev@gmail.com` (dates and content unchanged)
- [ ] Force-push the rewritten branches and tags to GitHub
- [ ] Final secret and data check over files and git history, right before publishing
- [ ] Flip repository visibility to public on GitHub (done manually in the GitHub settings)
