# Architecture

The agent ([`agent/mtd_strategy_selection_agent.py`](../agent/mtd_strategy_selection_agent.py)) runs an endless loop with three logical components. One iteration is one detection–deployment cycle.

## 1. Observer

- Invokes `dstat` with the command from [`config.yaml`](../agent/config.yaml) (`dstatCommand`). The command enables CPU, memory, filesystem, disk, network, TCP, socket, system and process metrics with per-second timestamps.
- Takes the last `historyLen` timestamped samples (default 10) from the `dstat` output.
- For each sample, extracts the numbers with a regular expression and strips unit suffixes (`k` → ×1000, `M` → ×1 000 000, `B` → ×1).
- Averages every metric across the window, producing one value per metric name (metric names are listed in [`agent/metrics_labels.py`](../agent/metrics_labels.py)).

## 2. Policy engine

- Loads the rules from [`policy_db.csv`](../agent/policy_db.csv). Each rule is `metric,sign,threshold,strategy`.
- For every averaged metric, checks each rule for that metric:
  - `<=` rule and value below threshold → a **positive hit** for the rule's strategy.
  - `>=` rule and value above threshold → a **positive hit**.
  - otherwise → a **negative hit**.
- Tracks, per strategy, `[positive, negative, ratio]` where `ratio = positive / (positive + negative)`.
- Ranks the strategies by either absolute positive hits (`evaluationMethod: 0`) or hit ratio (`evaluationMethod: 2`).

## 3. Deployment

- Picks the top-ranked strategy. If its ratio meets `detectionThreshold` (default 0.6), the agent `chdir`s to the strategy's directory and runs the corresponding command from `config.yaml` via `subprocess.call` (which waits for completion), then sleeps 60 seconds.
- If the threshold is not met, no command runs.
- Every decision is logged: metric-level detail to `observer.log`, deployment decisions to `deployer.log`.

## Strategy mapping

| Strategy | Threat | Command key | Script |
|---|---|---|---|
| MTD1 | Ransomware | `ransomwareMTD` | [`CreateDummyFiles.py`](../agent/MTD/Ransomware/CreateDummyFiles.py) |
| MTD2 | Command & control | `cncMTD` | [`ChangeIpAddress.py`](../agent/MTD/CnC/ChangeIpAddress.py) |
| MTD3 | Rootkit | `rootkitMTD` | [`RemoveRootkit.py`](../agent/MTD/Rootkit/RemoveRootkit.py) |
| MTD4 | Command & control | `cncMTD` | [`ChangeIpAddress.py`](../agent/MTD/CnC/ChangeIpAddress.py) |
