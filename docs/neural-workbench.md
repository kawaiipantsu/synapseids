# Neural training and live inference

The neural workbench provides **prepare → train → evaluate → shadow / activate** in
**ML → Training**. A separate Python worker performs training; `synapsed` keeps
capturing and scoring traffic throughout. Training does not activate a candidate.

## Quick start

1. Open **Training** and check **Training worker online**.
2. Choose **Attack / threat behavior** or **Application / traffic type**.
3. Select prepared corpora. For your own verified capture, expand **Import a
   labeled PCAP / PCAPNG**, choose its true label and prepare it. This assigns
   that label to every flow: mixed captures require per-flow labels offline.
4. Choose a candidate name, network size and epochs. For threats, adjust the
   false-positive and missed-attack costs. Start with the defaults.
5. Select **Train candidate**. Follow the run's loss and validation curves.
6. Select **Evaluate run**. Inspect supported classes, sample counts, held-out
   metrics and the confusion matrix, including normal traffic mistakes.
7. For a threat candidate, select **Run in shadow** to compare it against the
   current detector without changing alert decisions. Open **Live inference**.
8. Select **Activate candidate** only when its evaluation and your network's
   reviewed traffic support promotion. Activation replaces the model in that
   task's role. Models must be explicitly reactivated after a daemon restart.

The application task has an independent role: application predictions never turn
traffic into an attack. IRC or a collaboration service can carry either benign
or malicious activity. A failed inference is reported as unavailable.

## Reward, punishment and reviewed corrections

This is supervised learning, not reinforcement learning on live packets.
Class-balanced, weighted cross-entropy penalizes mistakes. Increasing the
**false-positive cost** increases the loss for misclassifying normal examples;
**missed-attack cost** increases the loss for mistakes on attack examples. These
weights are training priorities, not promises about the resulting alert rates.

Correct or confirm flows in **Review**, then choose **Use reviewed flows** in
Training. This creates a new immutable corpus from retained temporal vectors and
explicit human decisions in the current daemon session. Unsure, ignored and
unreviewed traffic is omitted. If the underlying flow has aged out, it cannot be
exported. Reviewer identities, notes, addresses and prior model predictions are
not training inputs. Repeated exports are deduplicated when training; conflicting
labels for the same conversation are rejected. Existing reviewed-label pickers
use the seven coarse threat classes; PCAP preparation supports detailed classes.

Neither blocklist matches nor a model's unreviewed predictions silently become
training truth. Do not mark busy owned servers "normal" merely to hide an alert:
use the editable OWNED rule and selective suppression under **Network policy**.

## What the network receives

The new `traffic-behavior-v1` feature schema contains 160 numeric inputs:

| Inputs | Meaning |
| --- | --- |
| 0–47 | The unchanged `flow-features-v1` values: counts, duration, rates, sizes, TCP flags/windows, ports, protocol and coarse network direction |
| 48–79 | Last 32 packet gaps, ordered oldest first and left padded |
| 80–111 | Last 32 packet sizes, signed by flow direction |
| 112–127 | Sampling coverage, gap moments/quantiles, lag correlations, repeat/burst ratios and direction changes |
| 128–143 | DNS counts, NXDOMAIN, name-shape statistics, HTTP/download hints, TLS/IRC observations and capture completeness |
| 144–159 | Bounded 60-second source context: port/address fan-out, one-way ratios, connection timing, DNS volume and periodicity |

The default network is a feed-forward network over the ordered temporal sketch:
**160 → 128 → 64 → outputs**. It learns from timing history; it is not a recurrent
network. Hidden widths of 64, 128 or 256 are available. Windows retain at most 32
packets and 64 conversations per source host, across at most 1,024 source hosts.
They describe this bounded sample, not all traffic ever seen.

Packet payloads, IP addresses, hostnames, reputation tags and human identity are
not numeric model inputs. Plaintext HTTP and complete TLS ClientHello/DNS
messages can supply bounded metadata. TCP reassembly, TLS decryption and QUIC
application decoding are not implemented. Split headers remain unknown.
Truncated capture data is not treated as malformed application traffic.

`flow-features-v1`, `traffic-classes-v1` and existing model families remain
unchanged. Detailed threat probabilities are also projected into the existing
seven-class alert contract. The original detailed distribution is retained.

## Threat and application coverage

`traffic-behavior-v1` models output `attack-classes-v2`: normal, scan, host sweep,
DoS/DDoS, SYN/UDP/ICMP floods, DNS exhaustion, brute force, botnet C2, malware, web
attack, RCE, phishing, DGA-like DNS, suspicious downloads, malformed traffic,
suspicious traffic and unknown.

`traffic-application-v1` models output `application-classes-v1`: unknown, DNS,
web, email, file transfer, remote access, streaming, IRC, Teams, Slack, WhatsApp,
Signal, other chat and VoIP.

**An output slot is not evidence that its detector is trained.** The worker masks
classes with fewer than five training examples, lists unsupported classes in the
report and preserves the coverage information with the bundle. Five examples is
only a minimum to fit a class, not enough to establish useful generalization.
Encrypted applications need representative labeled captures; port 443 cannot
identify a chat service reliably.

Independent pattern evidence appears in Live inference: port scanning, host
sweeps, long high-entropy DNS names with repeated NXDOMAIN, DNS query pressure,
plaintext executable/script download hints, malformed DNS and periodic
connection starts. These are advisory heuristics, not learned probabilities or
proof of exploitation. Entropy alone does not flag DGA. Periodic legitimate
pollers and software downloads require context. Pattern hints do not themselves
change a model's verdict or trigger new alerts.

## Reading the animated neural graph

Open **Live inference** and select a neural model. A shadow model is marked
**experimental**. Select a flow or pause to inspect one decision.

The daemon reruns that flow's exact retained input through the loaded ONNX model.
It serves the trace only when the output reproduces the stored distribution.
The graph shows actual input and operation values, up to 12 sampled units per
operation, and actual sampled Dense weights and `input × weight` contributions.
Select a unit to inspect its value; the table exposes the full bounded tensor.
Animation is slowed for people to read; it does not measure neuron execution
latency. Contributions exclude bias and are not SHAP or causal attribution.

A fallback schematic is explicitly architecture-only. An aged-out input, an
unloaded model, an output mismatch or an oversized diagnostic graph yields an
unavailable message. No guessed activations are drawn. Reduced-motion settings
are respected.

## Installing the external worker

Build the offline extractor and daemon with `make build`. Use a separate Python
virtual environment and the trainer's pinned requirements. The worker needs the
same local model and training directories as the daemon.

```sh
python -m venv /opt/synapse-trainer/venv
/opt/synapse-trainer/venv/bin/pip install -r trainer/requirements.txt
PYTHONPATH=trainer /opt/synapse-trainer/venv/bin/python -m synapse_trainer.workbench \
  --api http://127.0.0.1:8080 \
  --workdir /var/lib/synapseids/training/workbench \
  --models /var/lib/synapseids/models \
  --schemas ./schemas \
  --extractor ./synapse-extract
```

Set daemon `training.directory` to `/var/lib/synapseids/training` and
`models.directory` to `/var/lib/synapseids/models`. When API authentication is
enabled, add `--token-file /run/secrets/synapse-training-token`; the file contains
an admin bearer token. Keep it outside Git. The worker refuses redirects.
Run it under your service manager with a private working directory and logs.

Limits: one leased job at a time, four pending jobs, 200 job history entries,
100 epochs, 100,000 selected rows, four CPU threads, 128 MiB per uploaded capture,
32 uploaded captures / 1 GiB upload quota. Packet extraction has a five-minute
budget and a 16,384 active-flow cap. Data preparation and corpus retention are
local; remove unused upload files administratively when the quota is reached.
An absent worker leaves jobs queued. A lost worker lease fails the job without
activation. Cancellation is checked between training batches after heartbeat
notification; an already-running offline extraction can finish before stopping.

## Offline preparation and reproducibility

```sh
./synapse-extract --pcap verified-normal.pcap --label normal > normal.jsonl
./synapse-extract --pcap mixed.pcap --ctu-labels official.binetflow > labeled.jsonl
```

The second command is specific to CTU-13's documented August 2011 CEST flow
labels. It joins the oriented tuple and time interval, allowing five seconds for
capture clock skew, and retains `From-Botnet` / `From-Normal` labels only.
`To-Botnet` and background traffic do not become attack labels. Never apply that
label reader to a different dataset's timestamp or label format.

To prepare the matching manifest and make an offline CTU corpus visible to the
workbench, run this under the worker environment with a new corpus ID:

```python
from pathlib import Path
from synapse_trainer.workbench import prepare
prepare(
    Path("/var/lib/synapseids/training/workbench"),
    Path("/usr/local/bin/synapse-extract"),
    Path("/private/corpora/official-capture.pcap"),
    "", "attack", "Official annotated capture",
    corpus_id="annotated-capture-v1",
    official_labels=Path("/private/corpora/official.binetflow"),
)
```

Set `PYTHONPATH` to the repository's `trainer` directory. Preserve source URLs,
license, capture digest and labeling decisions beside the private corpus; never
reuse an ID to overwrite a corpus used by an evaluated bundle. The UI importer
creates unique IDs automatically.

Each row contains the 160 values, label, capture group, hashed conversation and
start time. Prepared corpus manifests contain row/class counts, data digest,
source and limitations. The worker verifies the digest. Model bundles retain the
recipe, source manifest versions, seed, normalizer, ONNX hash and test metrics.
A private prepared corpus is not automatically published.

Within each capture, conversations are sorted chronologically into 60/20/20
train/validation/test partitions. A 60-second embargo removes rows near the two
boundaries for captures spanning at least five minutes. Small captures explicitly
report the weaker split; captures with fewer than five conversations contribute
only to training. A job requires at least five rows in every final partition and
two supported classes. Signed-log transforms reduce heavy-tailed count/rate ranges; standardization is fitted on training data only and clipped to ±8. The exact transform and constants are saved in each bundle. The best
validation-loss checkpoint is evaluated on the untouched test partition.
This is **same-capture temporal evaluation**, not independent-site validation.

## Observability and troubleshooting

`/metrics` includes worker liveness, queue states, epochs/loss/validation metrics,
rich-input coverage, detailed threat classes and independent application counts.
The Grafana Neural Network dashboard includes panels for these series. Counters
count classification events, including snapshots, rather than unique sessions.
A shadow threat model does not increment the primary detailed-threat counter.

| Symptom | Check |
| --- | --- |
| Worker offline | Worker process, API bind address, token permissions and private log |
| No rich inputs | Sensor `flow-rich` mode, updated daemon/sensor, or local raw capture |
| Preparation fails | Supported Ethernet/RAW PCAP headers, extraction limits and valid labels |
| Too few partitions/classes | Add diverse labeled captures; do not duplicate rows to fake evaluation |
| Candidate fails registration | Bundle dimensions, schema, fitted normalizer and native ONNX operator support |
| No activation trace | Select a neural model and a retained classified flow; check mismatch message |
| No Teams/Signal output | Check actual class coverage; acquire labeled application captures |
| Neural predictions look noisy | Use shadow comparison, review mistakes, improve normal coverage and retrain |
