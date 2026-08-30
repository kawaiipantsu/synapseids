# THUGS(red) SynapseIDS

> Neural Network Intrusion Detection & Live Traffic Analysis

## 1. Purpose

THUGS(red) SynapseIDS is a network intrusion detection and traffic-classification platform built around a Go capture/flow daemon, configurable neural-network classifiers, dataset/model management, and a live web UI.

The system must support both real-time and offline traffic sources, convert packets into stable versioned flow features, classify those flows with neural-network models, expose all results live in the browser, and provide an integrated workflow for creating datasets, training models, comparing models, reviewing classifications, and deploying new model versions.

This project is intended for authorized defensive monitoring, lab traffic analysis, research, and training environments.

## 2. Core Design Principles

1. **Go owns the data plane.** Packet capture, decoding, flow tracking, feature extraction, inference orchestration, APIs, streaming, and sensor operation should be implemented in Go.
2. **Training may use Python.** Use PyTorch or an equivalent mature ML framework for training and export deployable models to ONNX.
3. **Stable ML contracts.** Input and output dimensions are locked within a model family. Hidden layers and training parameters are configurable.
4. **Version everything.** Feature schemas, output schemas, datasets, training recipes, normalizers, models, and model families must have explicit versions.
5. **Packets become flows; flows become features.** Do not couple packet-capture implementations directly to ML inference.
6. **Live-first UI.** Important operational views must update continuously without page reloads.
7. **Multiple models are normal.** The system should be able to score the same flow with production, location-specific, global, anomaly, and experimental models.
8. **Explain classifications.** Operators must be able to inspect the exact feature vector and model outputs associated with a decision.
9. **Safe model deployment.** A model whose feature/output contract is incompatible with the daemon must be rejected before inference.
10. **Modular capture.** New capture transports should be adapters, not special cases throughout the codebase.

## 3. Initial Architecture

```text
                         ┌──────────────────────────┐
                         │       Web Browser        │
                         │ Live UI / Training / SOC │
                         └────────────┬─────────────┘
                                      │ HTTP + WebSocket
                                      ▼
┌───────────────┐          ┌──────────────────────────┐
│ Remote Sensor │─────────▶│        synapsed          │
│ / SSH capture │          │                          │
└───────────────┘          │ Capture Manager          │
                           │ Packet Decoder            │
┌───────────────┐          │ Flow Engine               │
│ Local NIC     │─────────▶│ Feature Engine            │
└───────────────┘          │ Model Runtime             │
                           │ Event Bus                 │
┌───────────────┐          │ API / Live Stream         │
│ PCAP/PCAPNG   │─────────▶│ Persistence               │
└───────────────┘          └───────────┬──────────────┘
                                       │
                         ┌─────────────┴──────────────┐
                         │                            │
                         ▼                            ▼
                 ┌──────────────┐             ┌───────────────┐
                 │ Local Store  │             │ synapse-trainer│
                 │ SQLite first │             │ Python/PyTorch │
                 └──────────────┘             └───────┬───────┘
                                                      │
                                                      ▼
                                             ONNX + metadata
```

## 4. Suggested Repository Layout

```text
synapseids/
├── cmd/
│   ├── synapsed/             # Main daemon
│   ├── synapse/              # Administrative CLI
│   └── synapse-sensor/       # Optional lightweight remote sensor
├── internal/
│   ├── capture/
│   │   ├── interface/
│   │   ├── pcap/
│   │   ├── ssh/
│   │   ├── stream/
│   │   └── replay/
│   ├── packet/
│   ├── flow/
│   ├── features/
│   ├── inference/
│   ├── models/
│   ├── datasets/
│   ├── events/
│   ├── storage/
│   ├── api/
│   ├── websocket/
│   └── config/
├── pkg/
│   └── protocol/             # Shared sensor/API structures if needed
├── trainer/
│   ├── synapse_trainer/
│   ├── tests/
│   ├── requirements.txt or pyproject.toml
│   └── Dockerfile
├── web/
│   ├── src/
│   └── package.json
├── schemas/
│   ├── features/
│   ├── outputs/
│   └── events/
├── models/                   # Development models only; production path configurable
├── testdata/
│   ├── pcap/
│   └── features/
├── docs/
├── deployments/
├── PROJECT.md
└── README.md
```

## 5. Components

### 5.1 `synapsed`

The primary Go daemon.

Responsibilities:

- manage capture sources;
- decode packets;
- construct bidirectional flows;
- calculate feature vectors;
- run one or more inference models;
- calculate combined risk/classification results;
- persist flows, classifications, datasets, models, and metadata;
- expose REST APIs;
- stream live events to browsers;
- orchestrate training jobs;
- hot-load compatible models;
- expose health and performance telemetry.

### 5.2 `synapse`

Administrative CLI.

Possible commands:

```text
synapse status
synapse capture list
synapse capture add ...
synapse models list
synapse models activate <id>
synapse datasets list
synapse replay <capture.pcap> --speed 10
synapse training start <recipe>
```

Do not duplicate business logic in the CLI. It should primarily communicate with `synapsed`.

### 5.3 `synapse-sensor`

Optional lightweight Go capture agent for distributed installations.

Sensor modes:

- `raw`: stream packet/capture records;
- `flow`: aggregate into flows remotely;
- `feature`: send only calculated feature vectors.

Connections must be authenticated and encrypted. Design the protocol so sensors can reconnect and identify their location and sensor ID.

### 5.4 `synapse-trainer`

Python training worker/service.

Responsibilities:

- load one or more datasets;
- validate feature/output schema compatibility;
- construct configurable hidden architectures;
- normalize features;
- perform train/validation/test splits;
- train classifiers;
- produce metrics;
- export ONNX;
- export normalizer and metadata;
- report training progress live to `synapsed`.

The Go daemon must not depend on Python for normal inference.

## 6. Capture Sources

Implement capture sources behind a common interface.

Required initial adapters:

### Local network interface

Listen directly on a selected network interface.

### PCAP / PCAPNG

Read stored capture files for analysis, dataset generation, and replay.

### tcpdump stream

Accept a stream produced by tcpdump-compatible capture output.

### SSH remote tcpdump

Allow an authorized remote capture such as conceptually:

```text
ssh sensor-host tcpdump -U -w - <capture-filter>
```

The application should manage the subprocess/SSH stream rather than requiring temporary capture files.

### PCAP-over-IP

Provide a framed authenticated network transport for streaming capture records from remote systems. Prefer a clearly versioned protocol. Consider TLS over TCP initially and QUIC later.

### Replay

Replay PCAP traffic through the same processing pipeline at:

- 0.5x;
- 1x;
- 2x;
- 10x;
- maximum throughput;
- configurable custom speed.

Replay must use the normal flow/feature/classification pipeline so UI behavior matches live traffic.

## 7. Flow Engine

Represent traffic primarily as bidirectional flows based on a normalized 5-tuple:

```text
source IP
source port
destination IP
destination port
transport protocol
```

The flow engine should normalize direction while retaining initiator/responder semantics where known.

Flows should close or emit final records on:

- TCP FIN/RST;
- inactivity timeout;
- maximum configured flow lifetime;
- capture termination.

Long-lived flows should emit periodic snapshots so classification does not wait indefinitely for flow completion.

Every flow needs a stable internal ID.

## 8. Feature Schema

Start with a `flow-features-v1` schema containing roughly 40–60 numeric/categorical-derived features.

Candidate features:

```text
flow_duration
packets_forward
packets_backward
bytes_forward
bytes_backward
packet_size_mean
packet_size_min
packet_size_max
packet_size_stddev
forward_packet_size_mean
backward_packet_size_mean
packets_per_second
bytes_per_second
forward_packets_per_second
backward_packets_per_second
interarrival_mean
interarrival_min
interarrival_max
interarrival_stddev
forward_interarrival_mean
backward_interarrival_mean
source_port
destination_port
protocol_tcp
protocol_udp
protocol_icmp
tcp_syn_count
tcp_ack_count
tcp_fin_count
tcp_rst_count
tcp_psh_count
tcp_urg_count
syn_ack_ratio
packet_direction_ratio
byte_direction_ratio
initial_tcp_window
average_tcp_window
retransmission_count
duplicate_ack_count
source_unique_dst_ports_1s
source_unique_dst_ports_10s
source_unique_dst_hosts_1s
source_unique_dst_hosts_10s
source_connections_1s
source_connections_10s
source_failed_connection_ratio
destination_port_rarity
source_activity_score
small_packet_ratio
large_packet_ratio
average_payload_length
payload_entropy
bidirectional_flag
internal_to_internal
internal_to_external
external_to_internal
```

Exact features should be finalized before `flow-features-v1` is frozen.

Avoid feeding raw IP addresses directly into the neural network. Prefer derived behavioral/context features so the model does not simply memorize hosts from training data.

Every feature must define:

- name;
- index;
- type;
- unit;
- calculation;
- missing-value behavior;
- normalization behavior.

Once released, never silently change the meaning or ordering of a versioned feature schema.

## 9. Output Schema

Initial `traffic-classes-v1` proposal:

```text
0 normal
1 scan
2 dos_ddos
3 brute_force
4 botnet_c2
5 web_attack
6 suspicious
```

The exact output class count is locked for models belonging to this family.

Do not treat `suspicious` as a replacement for anomaly detection. It is a supervised class. An anomaly/novelty score should eventually be produced by a separate model.

## 10. Neural Network Contract

A model family defines locked input/output contracts.

Example:

```text
family: flow-classifier-v1
feature_schema: flow-features-v1
input_size: 56
output_schema: traffic-classes-v1
output_size: 7
```

The actual input count above is illustrative until the final v1 feature list is frozen.

Within the family, hidden architecture is configurable.

Examples:

```text
56 -> 64 -> 32 -> 7
56 -> 128 -> 64 -> 32 -> 7
56 -> 256 -> 256 -> 128 -> 64 -> 7
```

Configurable hidden-layer properties should include:

- width;
- activation;
- dropout;
- batch normalization;
- optional residual blocks when supported.

Training configuration should separately expose:

- optimizer;
- learning rate;
- batch size;
- epochs;
- early stopping;
- class weighting;
- scheduler;
- random seed.

The UI must lock input and output layers while allowing hidden layers to be edited.

If a future feature schema needs 72 inputs, create a new model family/version rather than mutating `flow-classifier-v1`.

## 11. Model Artifact

A deployable model should be a self-describing bundle, for example:

```text
model-bundle/
├── model.onnx
├── metadata.json
├── normalizer.json
├── metrics.json
└── training-recipe.json
```

Metadata should include at least:

```text
model_id
name
version
family
feature_schema
input_size
output_schema
output_size
architecture
training_dataset_ids
created_at
trainer_version
parameter_count
model_hash
```

The daemon must validate the model bundle before activation.

## 12. Multiple Models and Model Roles

Support multiple loaded models.

Suggested roles:

- `primary`: authoritative supervised classifier;
- `location`: model specialized for a site;
- `global`: model trained across locations;
- `experimental`: shadow model whose predictions are recorded but do not drive alerts;
- `anomaly`: separate novelty/anomaly detector.

A flow may therefore produce:

```text
Primary:       scan    0.96
Global:        scan    0.81
Location:      normal  0.63
Experimental:  scan    0.99
Anomaly:       0.88
```

Store individual model outputs, not only the final combined decision.

Model disagreement should itself be queryable and visible in the UI.

## 13. Anomaly Detection

After the supervised classifier is functional, add a separate anomaly model such as an autoencoder.

Conceptually:

```text
flow features
   ├── supervised classifier -> class probabilities
   └── autoencoder           -> reconstruction/anomaly score
```

This permits cases such as:

```text
Classifier: NORMAL 92%
Anomaly score: 0.94
Final state: UNKNOWN / SUSPICIOUS
```

Do not force unknown behavior into a known attack class simply because softmax always has a maximum.

## 14. Datasets

Datasets are first-class versioned objects.

A dataset should record:

- ID;
- name;
- description;
- location/site;
- tags;
- creation time;
- source capture IDs;
- time ranges;
- feature schema;
- output schema;
- number of flows;
- label counts;
- labeling source;
- parent datasets;
- immutable content hash/version.

Examples:

```text
thugs/lab-attacks-2026-08
hq-copenhagen/baseline-2026-08
hq-copenhagen/reviewed-anomalies-2026-09
global/multi-site-2026-09
```

A training recipe must be able to combine multiple compatible datasets with optional weighting.

Example:

```text
70% Copenhagen normal baseline
20% known attack corpus
10% manually reviewed local detections
```

Never leak the test split into training. Dataset splitting must be reproducible and recorded in model metadata.

## 15. Location-Specific Training

Locations should be explicit entities rather than free-form strings wherever practical.

A model may be:

- global;
- location-specific;
- environment-specific (lab, office, datacenter, cloud);
- derived/fine-tuned from another model.

Track lineage:

```text
Global-v1
├── Copenhagen-v1
│   └── Copenhagen-v2
├── London-v1
└── AWS-v1
```

The model registry should expose this lineage.

## 16. Human Review Loop

Every classification should be reviewable.

Review states:

```text
unreviewed
correct
incorrect
unsure
ignored_pattern
```

Allow an operator to assign or correct a label. Reviewed flows can be exported into a curated dataset.

Desired lifecycle:

```text
capture
  -> classification
  -> human review
  -> curated dataset
  -> retraining
  -> evaluation
  -> deployment
```

Always retain the original model prediction separately from the human-reviewed label.

## 17. Live Event Architecture

Use an internal event abstraction from the beginning.

Candidate events:

```text
CaptureSourceConnected
CaptureSourceDisconnected
PacketReceived
FlowStarted
FlowUpdated
FlowClosed
FeaturesGenerated
ClassificationCreated
ModelDisagreementDetected
AlertCreated
ReviewUpdated
TrainingStarted
TrainingEpochCompleted
TrainingCompleted
ModelRegistered
ModelActivated
ModelDeactivated
SensorConnected
SensorDisconnected
```

An in-process Go event bus/channels are sufficient initially. Do not introduce Kafka/NATS until distribution actually requires it, but avoid coupling consumers directly to producers.

## 18. API

Expose a versioned HTTP API, for example `/api/v1/...`.

Initial resource groups:

```text
/api/v1/status
/api/v1/captures
/api/v1/flows
/api/v1/hosts
/api/v1/classifications
/api/v1/detections
/api/v1/datasets
/api/v1/models
/api/v1/training
/api/v1/sensors
/api/v1/replay
/api/v1/settings
```

Use WebSockets for the main bidirectional live channel. Server-Sent Events may be used for simple one-way streams if useful, but avoid maintaining two competing live protocols without reason.

Do not send every raw packet to every browser. Stream aggregated telemetry and relevant flow/classification events with server-side filtering and backpressure.

## 19. Web UI

The UI must be operationally useful, not merely an ML demonstration.

Suggested top-level navigation:

```text
LIVE
  Dashboard
  Flow Log
  Investigate
  Hosts
  Detections

CAPTURE
  Sources
  Sensors
  Replay

ML
  Models
  Training
  Datasets
  Architecture
  Model Compare
  Drift

SYSTEM
  Performance
  Storage
  Settings
```

### 19.1 Dashboard

Live cards/graphs for:

- traffic throughput;
- packets/sec;
- flows/sec;
- active flows;
- active hosts;
- classification counts;
- anomaly counts;
- top talkers;
- top destination ports;
- protocol breakdown;
- sensor health;
- recent detections;
- model inference latency.

### 19.2 Full-Screen Rolling Flow Classification Log

This is a primary product view.

It must support a true full-screen/kiosk mode and continuously append classifications.

Example:

```text
23:14:02.381 HQ-01 10.20.4.18:51222 -> 1.1.1.1:443    TCP NORMAL      99.7%
23:14:02.402 HQ-01 10.20.7.41:43112 -> 10.20.8.0:22  TCP SCAN        96.4%
23:14:02.410 AWS-2 172.16.2.9:55321 -> 52.x.x.x:443  TCP NORMAL      98.1%
23:14:02.425 LAB-4 192.168.50.8 -> 192.168.50.1       ICMP SUSPICIOUS 71.2%
```

Required behavior:

- auto-scroll;
- pause/resume without dropping backend events;
- resume-to-latest;
- configurable maximum retained browser rows;
- compact/comfortable density;
- column chooser;
- sorting when paused;
- filters;
- search;
- class filters;
- minimum confidence;
- sensor/location filter;
- model filter;
- protocol filter;
- source/destination filters;
- highlight suspicious traffic;
- highlight low-confidence predictions;
- highlight model disagreement;
- pin rows;
- open flow inspector from a row;
- keyboard navigation;
- wallboard/kiosk mode;
- replay traffic should appear through the same view.

The backend must protect the browser from overload. Batch updates and provide bounded queues/backpressure behavior.

### 19.3 Flow Inspector

For a selected flow show:

- full tuple and direction;
- source/sensor/location;
- start/end/duration;
- packet/byte statistics;
- TCP metadata;
- all raw feature values;
- normalized model inputs;
- model/version used;
- complete class probability vector;
- anomaly score;
- model disagreements;
- historical snapshots of the flow;
- human review status.

Provide a useful explanation panel such as top feature contributions or deviation from training baseline.

Example:

```text
Classification: SCAN
Confidence: 97.3%

Feature                    Current     Baseline
unique_dst_ports_10s       96          1-4
connections_10s            421         2-18
syn_ack_ratio               8.7        0.8-1.4
packet_size_mean            62 B       400-900 B
```

### 19.4 Investigation Mode

Selecting a host should pivot the application around that entity.

Show:

- live flows;
- classification history;
- destinations;
- ports;
- traffic volume;
- behavioral baseline;
- anomaly history;
- unusual features;
- related detections;
- model disagreement;
- first/last seen.

### 19.5 Hosts

Maintain observed host profiles including:

- first seen;
- last seen;
- addresses;
- traffic volume;
- common protocols/ports;
- common peers;
- classifications;
- baseline behavior;
- anomaly trend.

### 19.6 Classification Timeline

Provide live/historical time-series visualization for classification volume and anomaly scores. Clicking a time range should filter flows/detections to that range.

### 19.7 Model Comparison

Allow side-by-side evaluation of multiple compatible models against:

- live shadow traffic;
- a selected dataset;
- a PCAP replay.

Compare:

- predictions;
- confidence;
- disagreement;
- accuracy/F1 when labels exist;
- inference latency;
- confusion matrices.

### 19.8 Training

Live training view should display:

- status;
- epoch;
- batches;
- training loss;
- validation loss;
- accuracy;
- precision;
- recall;
- F1;
- per-class metrics;
- confusion matrix;
- learning rate;
- elapsed time;
- CPU/GPU usage when available.

Training events should update live.

### 19.9 Architecture Builder

Input/output layers are shown as locked.

Example:

```text
INPUT 56 [LOCKED]
    |
Dense 256 / ReLU / BatchNorm / Dropout 0.30
    |
Dense 128 / ReLU / Dropout 0.20
    |
Dense 64 / ReLU
    |
OUTPUT 7 [LOCKED]
```

Allow adding, deleting, and reordering hidden layers.

Continuously estimate:

- parameter count;
- approximate model size;
- rough inference complexity.

Warn about architectures that are obviously excessive relative to the feature dimensionality, but do not arbitrarily prevent experimentation.

### 19.10 Dataset Manager

Support:

- dataset creation;
- metadata/tags;
- label distribution;
- source captures;
- location;
- schema;
- merge/derive operations;
- class imbalance warnings;
- duplicate warnings;
- train/validation/test planning;
- manual review inclusion.

### 19.11 Dataset Explorer

Visualize:

- feature distributions;
- label distributions;
- correlations;
- outliers;
- protocol/port distributions;
- location differences;
- PCA/UMAP projections where useful.

### 19.12 Model Registry

Each model page should show:

- model/version;
- family;
- input/output schema;
- architecture;
- datasets;
- lineage;
- metrics;
- confusion matrix;
- parameter count;
- artifact size;
- inference benchmarks;
- deployment status;
- creation time;
- content hash.

### 19.13 Drift

Compare current feature distributions with model training distributions.

Show drift per feature and overall drift state. Drift is informational initially; do not automatically retrain/deploy models without an explicit policy and operator approval.

### 19.14 Capture Sources

Manage local interfaces, PCAP inputs, SSH captures, network streams, and sensors.

Display:

- state;
- packets/sec;
- bytes/sec;
- drops;
- connection latency where relevant;
- last packet time;
- current filter;
- error state.

### 19.15 Sensor Topology

Represent sensors grouped by location/environment. Clicking a location or sensor should be able to scope other UI views.

### 19.16 System Performance

Expose:

- CPU;
- memory;
- goroutines;
- capture drops;
- packet decode latency;
- flow table size;
- feature extraction latency;
- inference p50/p95/p99;
- classifications/sec;
- event queue depth;
- WebSocket clients;
- database latency/size;
- trainer status.

## 20. Storage

Start with SQLite for metadata and moderate development workloads.

Design repository/storage interfaces so a higher-volume backend can be added later. ClickHouse is a likely future choice for large flow/classification history.

Do not store packet payloads indefinitely by default.

Suggested retention categories:

- flow metadata;
- feature vectors;
- classifications;
- model outputs;
- alerts/detections;
- review decisions;
- capture metadata;
- optional bounded packet/capture samples associated with detections.

Retention policies must be configurable.

## 21. Security Requirements

This application handles sensitive network telemetry. Treat security as part of the architecture.

Required principles:

- bind management UI/API to localhost by default unless explicitly configured;
- authenticate non-local UI/API access;
- TLS for remote sensors and remote UI deployments;
- authenticated sensor identity;
- least-privilege capture permissions;
- avoid running the entire daemon as root where platform capabilities can isolate capture privileges;
- secrets must not be written to logs;
- SSH credentials/keys must use secure OS/config mechanisms;
- validate uploaded PCAP/model/dataset inputs;
- cap decompression/file/resource consumption;
- use bounded queues;
- defend the UI/API against untrusted packet-derived strings;
- maintain an audit log for model activation, training, dataset edits, and human label changes;
- require explicit action to deploy a newly trained model;
- remote capture must only operate against systems the operator is authorized to monitor.

## 22. Performance Principles

The packet path must avoid unnecessary allocations.

Priorities:

1. do not block packet ingestion on UI/storage;
2. use bounded worker queues;
3. batch inference where it improves throughput without unacceptable latency;
4. batch WebSocket updates;
5. measure packet drops explicitly;
6. expire flow state efficiently;
7. avoid persisting every packet unless specifically configured;
8. expose profiling/metrics early.

Correctness and observability come before premature micro-optimization.

## 23. Configuration

Prefer one explicit configuration file plus environment-variable overrides for secrets/deployment concerns.

Example areas:

```yaml
server:
  listen: 127.0.0.1:8080

storage:
  driver: sqlite
  path: ./data/synapse.db

capture:
  flow_idle_timeout: 30s
  flow_max_lifetime: 5m

models:
  directory: ./data/models
  primary: null

live:
  websocket_batch_ms: 100
  client_queue_size: 5000

retention:
  flows: 30d
  classifications: 90d
```

Do not commit credentials into configuration examples.

## 24. Observability

The daemon should provide structured logs and metrics.

At minimum instrument:

- packet counters;
- packet drops;
- capture errors;
- active flows;
- flow creation/expiration rate;
- feature extraction rate;
- inference latency;
- inference failures;
- classifications by class;
- model disagreement;
- storage latency;
- live-client queue drops;
- sensor connectivity;
- training job state.

## 25. Testing Strategy

### Unit tests

Cover:

- packet-to-flow normalization;
- flow timeout behavior;
- feature calculations;
- normalization;
- model contract validation;
- dataset compatibility;
- event filtering;
- retention logic.

### Golden feature tests

Maintain small known PCAPs and expected feature vectors. Feature extraction changes must not silently alter a released schema.

### Integration tests

Test:

```text
PCAP -> flow -> feature -> inference -> classification -> API/storage
```

and:

```text
trainer -> ONNX bundle -> daemon validation -> inference
```

### Load tests

Measure:

- packets/sec;
- concurrent flows;
- classifications/sec;
- WebSocket fan-out;
- memory growth;
- queue overflow behavior.

## 26. Development Phases

### Phase 1 — Vertical Slice

Build the smallest complete path:

```text
PCAP file
 -> packet decoder
 -> flow engine
 -> fixed v1 features
 -> dummy/simple classifier
 -> REST API
 -> WebSocket
 -> rolling live flow log
```

The UI must already show live/replayed classifications.

### Phase 2 — Real Inference

Add:

- Python trainer;
- configurable hidden layers;
- ONNX export;
- Go ONNX inference;
- model bundles;
- model registry;
- compatibility validation.

### Phase 3 — Live Capture

Add:

- local interface capture;
- tcpdump stream;
- SSH tcpdump;
- capture-source UI;
- capture performance metrics.

### Phase 4 — Dataset/Training Workflow

Add:

- dataset manager;
- multiple training datasets;
- training recipes;
- live training dashboard;
- confusion matrices;
- model activation workflow.

### Phase 5 — Investigation

Add:

- flow inspector;
- host profiles;
- investigation mode;
- classification timeline;
- human review queue;
- curated datasets.

### Phase 6 — Distributed Sensors

Add:

- `synapse-sensor`;
- authenticated encrypted transport;
- raw/flow/feature modes;
- sensor topology;
- location metadata.

### Phase 7 — Advanced ML

Add:

- anomaly autoencoder;
- model comparison;
- shadow models;
- model disagreement views;
- drift monitoring;
- global/location model lineage.

### Phase 8 — Scale

Only when measurements require it, evaluate:

- AF_PACKET/eBPF capture;
- ClickHouse;
- NATS/Kafka;
- distributed inference;
- GPU inference;
- QUIC sensor transport.

## 27. Initial Technical Choices

Recommended defaults unless implementation evidence suggests otherwise:

```text
Backend/data plane:       Go
Packet parsing:           gopacket/libpcap initially
Training:                 Python + PyTorch
Deployment model format:  ONNX
Frontend:                 TypeScript + React (or equivalent modern SPA)
Live transport:           WebSocket
Metadata storage:         SQLite initially
API style:                REST + WebSocket
Charts:                   frontend charting library chosen for streaming performance
```

Do not overcommit to infrastructure before the vertical slice works.

## 28. Coding Rules for Claude

When implementing this project:

1. Read this file before making architectural changes.
2. Prefer small, testable packages with explicit interfaces.
3. Do not create abstractions without a concrete current use or obvious second implementation.
4. Keep capture, flow, features, inference, storage, and API boundaries separate.
5. Never change a released feature schema's order or semantics. Create a new schema version.
6. Never change a model family's input/output contract. Create a new family/version.
7. Add tests with every feature-calculation change.
8. Prefer deterministic/reproducible training behavior where possible.
9. Store training configuration and dataset versions with every model.
10. Do not activate newly trained models automatically.
11. Treat all packet-derived data as untrusted input.
12. Keep hot packet-processing paths independent of slow database/UI operations.
13. Avoid adding distributed infrastructure until profiling justifies it.
14. Keep APIs versioned.
15. Document significant architecture decisions in `docs/adr/`.
16. Before adding a dependency, explain what problem it solves and prefer mature maintained libraries.
17. Do not implement offensive actions, exploitation, automated counterattack, or traffic modification as part of the IDS. The product observes, classifies, explains, and alerts.
18. Ensure development/testing captures are authorized or synthetic.

## 29. Definition of Done for the First Usable Prototype

The first usable prototype is complete when a developer can:

1. start `synapsed`;
2. open the web UI;
3. load a PCAP;
4. replay it;
5. see flows created live;
6. see feature vectors generated;
7. see each flow classified;
8. watch classifications scroll in the full-screen rolling log;
9. pause and inspect an individual flow;
10. see raw and normalized features;
11. select a model and see its class probabilities;
12. create a labeled dataset from compatible flow records;
13. launch a training job using one or more datasets;
14. watch training metrics live;
15. receive an ONNX model bundle;
16. register and validate the model;
17. explicitly activate it;
18. replay the PCAP and see the new model used for classification.

This vertical slice is more important than implementing every capture backend or advanced visualization immediately.

## 30. Future Ideas

Keep these in mind but do not block the initial architecture on them:

- autoencoder anomaly detection;
- recurrent/temporal models using sequences of flows;
- per-host behavioral embeddings;
- protocol-specific specialist models;
- ensembles;
- active-learning queues that prioritize uncertain samples for review;
- automatic training-set quality recommendations;
- drift-triggered retraining suggestions;
- location-specific fine-tuning;
- model promotion stages (experimental -> candidate -> production);
- signed model artifacts;
- capture redaction/anonymization;
- role-based access control;
- alert integrations;
- historical incident workspaces;
- downloadable investigation reports;
- feature-space PCA/UMAP views;
- traffic matrices and topology views;
- long-term model performance tracking against human-reviewed labels.

## 31. Immediate Next Task

Start with Phase 1.

Before writing large amounts of code, define and commit:

1. the Go module/repository skeleton;
2. capture-source interface;
3. normalized packet representation;
4. flow key and flow lifecycle;
5. the exact `flow-features-v1` schema;
6. the initial `traffic-classes-v1` schema;
7. live event structures;
8. minimal REST/WebSocket contracts;
9. golden PCAP test fixtures;
10. a basic web UI containing the rolling classification log.

Then implement one end-to-end PCAP replay path before adding additional capture methods.
