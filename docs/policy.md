# Policy database

The policy database [`agent/policy_db.csv`](../agent/policy_db.csv) is the knowledge that drives detection. It is a headerless CSV; each line is one rule.

## Rule format

```
metric,sign,threshold,strategy
```

| Field | Meaning |
|---|---|
| `metric` | A `dstat` metric name (see [`metrics_labels.py`](../agent/metrics_labels.py)), e.g. `idl`, `writ`, `recv` |
| `sign` | `<=` or `>=` — the direction that counts as suspicious |
| `threshold` | The averaged value the metric is compared against |
| `strategy` | The strategy the rule votes for: `MTD1`–`MTD4` |

## Current rules

| Metric | Condition | Votes for | Rationale |
|---|---|---|---|
| `idl` | `<= 50` | MTD1 | Low CPU idle — heavy encryption work |
| `sys` | `>= 24` | MTD1 | High system CPU |
| `usr` | `>= 10` | MTD1 | High user CPU |
| `writ` | `>= 200000` | MTD1 | High disk write rate |
| `writs` | `>= 20` | MTD1 | Many write operations |
| `tim` | `>= 6` | MTD2 | TCP time-wait sockets from C&C traffic |
| `new` | `>= 17` | MTD3 | Many new processes — rootkit activity |
| `recv` | `>= 2500` | MTD4 | High network receive rate |

## How the policy was derived

The thresholds were synthesised from the measurement runs under [`visualizations/01-policy-synthesis/`](../visualizations/01-policy-synthesis/), which compare a healthy baseline against seven malware scenarios. The [Policy-Synthesis notebook](../visualizations/01-policy-synthesis/Policy-Synthesis.ipynb) shows how each metric separates malicious from benign behaviour and how the thresholds were chosen.
