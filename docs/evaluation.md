# Evaluation

The evaluation data and notebooks live under [`visualizations/`](../visualizations/). Each experiment folder contains a Jupyter notebook and the raw measurement data it reads.

## Experiments

| Folder | Notebook | What it measures |
|---|---|---|
| [`01-policy-synthesis/`](../visualizations/01-policy-synthesis/) | `Policy-Synthesis.ipynb` | Healthy baseline vs. seven malware scenarios; the basis for the [policy thresholds](policy.md) |
| [`02-evaluation/individual/`](../visualizations/02-evaluation/individual/) | `IndividualEvaluation.ipynb` | The agent against each malware scenario individually |
| [`02-evaluation/mixed/`](../visualizations/02-evaluation/mixed/) | `MixedEvaluation.ipynb` | The agent against a mixed attack sequence |
| [`02-evaluation/overhead/`](../visualizations/02-evaluation/overhead/) | `OverheadEvaluation.ipynb` | Runtime overhead of the agent, with and without it running |

## Malware scenarios

The policy-synthesis runs cover a healthy baseline plus: httpBackdoor, backdoor, The Tick, BASHLITE, Ransomware-PoC, BEURK and bdvl. The last two are `LD_PRELOAD` rootkits (countered by MTD3); the ransomware PoC is countered by MTD1; the remaining backdoor/C&C samples by MTD2/MTD4.

## Data layout

Each scenario folder holds:

- `*-log.csv` — the `dstat` metric log
- `*-netstatlog.txt` — a `netstat` capture
- `observer.log`, `deployer.log` — the agent's decision logs for that run
- `nohup.out` — captured stdout

## Reproducing the plots

```bash
uv sync --extra viz
```

Then open a notebook, for example:

```bash
uv run jupyter notebook visualizations/01-policy-synthesis/Policy-Synthesis.ipynb
```

> [!NOTE]
> The notebooks were authored in 2022 and read the CSVs from paths relative to their own folder. They are provided to document how the thesis figures were produced; some cells may need path adjustments to re-run end to end.
