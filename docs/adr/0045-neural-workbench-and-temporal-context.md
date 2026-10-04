# 0045 — Neural workbench and temporal traffic context

Accepted, 2026-10-04.

The requested training workflow needs an explicit prepare → train → evaluate →
activate path in the UI. The Go packet daemon remains independent of Python.
A separately started, bounded CPU worker claims validated training jobs, streams
metrics, writes bundles and registers completed candidates. Activation remains
an explicit operator action. Existing recipe/CLI workflows remain available.

The released 48-feature and seven-class contracts remain immutable. New families
consume a separate feature schema retaining ordered packet gaps and sizes,
DNS/HTTP metadata statistics, and bounded source-host windows. Missing telemetry
must have availability indicators, especially for older flow/feature sensors.
A versioned rich-flow sensor mode carries bounded metadata with no raw packet
payloads. Legacy raw/flow/feature modes remain readable.

Attack and application labels are independent tasks: chat or encrypted traffic
can also be malicious. Cost-sensitive supervised loss and reviewed corrections
implement the requested reward/punishment feedback, with explicit false-positive
and missed-attack weights. Predictions and reputation matches never silently
become ground-truth labels. Splits must keep correlated flows/captures together;
normalization is fitted on training data only. Evaluation and per-class coverage
travel with every bundle. Labels with no training support must remain unavailable.

The diagnostic runtime records actual ONNX operation outputs and bounded sampled
Dense weight contributions from a replayed forward pass. A trace is served only
when it reproduces the stored classification using its matching retained flow
version. It is not gradient/SHAP attribution. The UI animates these measured
values at human-readable speed and identifies sampled units. Normal inference
allocates no trace data.

Maltrail research informs bounded scan windows, NXDOMAIN counters, domain-label
entropy and repeated-interval analysis, together with honest advisory naming and
suppression. Shared feed sources include CINS Army. Reputation evidence stays
separate from learned output. Domain entropy alone is not proof of DGA; periodic
pollers are not automatically malware; executable extensions are not proof of an
infection. HTTPS/QUIC content is unavailable without an authorized decryption
source and is never invented.

Research references:

- [Maltrail source and MIT license](https://github.com/stamparm/maltrail)
- [Maltrail beacon heuristic](https://github.com/stamparm/maltrail/blob/master/sensor/src/heuristics/beacon.rs)
- [Maltrail DNS heuristics](https://github.com/stamparm/maltrail/tree/master/sensor/src/heuristics)
- [CTU-13 dataset](https://www.stratosphereips.org/datasets-ctu13)
- [ISCX VPN/non-VPN dataset](https://www.unb.ca/cic/datasets/vpn.html)
- [NIMS instant-messaging dataset project](https://project-enta.com/publications/)

Public PCAPs are downloaded to private, external corpus storage, with source,
license/attribution, digest and labeling assumptions. They are parsed offline,
never injected into a network. Mixed/infected-host captures require flow-level
annotations; file origin alone cannot label every packet malicious. Synthetic
fixtures remain labeled as fixtures and cannot substantiate general accuracy.

The separate `synapse-extract` binary is an explicit offline data-preparation
entry point. It reuses Go packet/flow/features code so Python does not reproduce
feature calculations. The `synapse` operator CLI remains HTTP-only. Python is
started separately and the daemon only leases declarative jobs. Reviewed-vector
export uses already-computed retained inputs; it never computes packet features
in the API. Historical reviews without current retained input are not guessed.

The concrete split is chronological conversation grouping within each capture,
with a 60-second embargo where capture duration permits. This gives temporal
holdout, not independent-capture/site validation. Reports must state that limit.
Classes with fewer than five training examples are masked; this minimum does not
establish practical coverage. The small starter remains a shadow candidate.
