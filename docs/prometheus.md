# Prometheus and Grafana

SynapseIDS already exposes **`GET /metrics` on the same listener as the UI**.
It returns Prometheus text exposition (`text/plain; version=0.0.4`). No separate
exporter, plugin, or feature flag is required. The endpoint follows native API
RBAC: a viewer token is sufficient when authentication is enabled.

## Scrape configuration

Merge the job in [contrib/prometheus/synapseids.yml](../contrib/prometheus/synapseids.yml)
into your Prometheus configuration. The example assumes Prometheus and the
locally bound daemon run on the same host; replace the target with the reachable
management address and port for a remote scraper. Use `credentials_file` for a
viewer token when needed, and HTTPS with verified trust for a TLS reverse proxy.
Credentials are read on the Prometheus host, not the SynapseIDS host.

Validate and reload using your normal Prometheus service procedure. If
`promtool` is installed:

```sh
promtool check config /etc/prometheus/prometheus.yml
```

In Prometheus Targets, verify the `synapseids` job is **UP**. Then query
`up{job="synapseids"}` and `synapseids_build_info{job="synapseids"}`. The
endpoint can include source identity labels; treat raw scrapes as operational
telemetry and avoid publishing live values in documentation.

## Ready-made Grafana dashboards

Import [Network Intelligence](../contrib/grafana/synapseids-operations.json) and
[Neural Network](../contrib/grafana/synapseids-neural-network.json), then select
your Prometheus data source (default name: `db-prometheus`). See the
[dashboard guide](../contrib/grafana/README.md) for setup and interpretation.

## Training, model, dataset and remote-sensor metrics

The visual workspace preview extends the same `/metrics` endpoint; a second
scrape job is unnecessary. New families include:

| Area | Metrics and interpretation |
|---|---|
| Training lifecycle | `synapseids_training_runs{status}`, one-hot `synapseids_training_run_status{run_id,status}`, epoch and planned epoch gauges, started/updated/finished Unix timestamps |
| Learning | `synapseids_training_loss`, `training_validation_loss`, validation accuracy/precision/recall/F1 ratios, reconstruction error, learning rate, elapsed seconds, per-epoch batches |
| Models | `synapseids_models_loaded{role}`, registered bundle count, per-model parameter count, artifact bytes, active flag and input width |
| Datasets | Versions, total rows across versions, and total CSV bytes; versions can overlap |
| Sensors | Per-source records, serialized record payload bytes, raw packets/bytes, reported capture drops and running state |

All metric names carry the `synapseids_` prefix. Per-run/per-model series cover
the **newest 100** entries. Aggregate counts cover all known entries. Metrics
never contain recipe text, arbitrary reporter fields, contact data or secrets.
The endpoint does contain operational IDs/source labels; protect access.

The worker must report to the daemon (`--report-to`, plus `SYNAPSE_API_TOKEN`
when required). A run without reported epochs has **no loss or accuracy series**.
Missing/non-numeric values are omitted. Validation accuracy is a ratio from the
worker's held-out validation set, not measured production detection accuracy.
Anomaly training may report reconstruction error without classification accuracy.

Training values are gauges. Do not apply `rate()` to loss, epoch or per-epoch
batches. Prometheus samples wall time; fast epochs may fall between scrapes.
Completed runs retain their latest observations until outside the newest-100
window. Per-run IDs accumulate historical time series under Prometheus retention.
An early-stopped completed run can legitimately remain below its planned epoch
budget. The console retains the individual reported epoch history.

Sensor counters reset on reconnect. Use `rate()` or `increase()`.
`synapseids_sensor_record_bytes_total` measures serialized flow/feature transport
payload, **not observed network bandwidth**. Raw-mode packet counters use
different units and are zero in record modes. Runtime classifier count includes
the heuristic fallback; it does not prove that a trained neural model is active.

## Grafana query examples

Add your Prometheus server as a Grafana data source. Grafana queries Prometheus,
not the SynapseIDS endpoint directly. Add panels using these expressions:

| Panel | PromQL | Unit |
|---|---|---|
| Classification rate by class | `sum by (instance, class) (rate(synapseids_classifications_total{job="synapseids"}[5m]))` | results/s |
| Packet rate | `rate(synapseids_capture_packets_total{job="synapseids",source="_all"}[5m])` | packets/s |
| Ingest bandwidth | `8 * rate(synapseids_capture_bytes_total{job="synapseids",source="_all"}[5m])` | bits/s |
| Capture drops | `rate(synapseids_capture_kernel_drops_total{job="synapseids",source="_all"}[5m])` | drops/s |
| Connected sensors | `synapseids_sensors_connected{job="synapseids"}` | count |
| Live flow-table occupancy | `synapseids_flows_active{job="synapseids"}` | count |
| Inference p95 | `histogram_quantile(0.95, sum by (instance, le) (rate(synapseids_inference_latency_seconds_bucket{job="synapseids"}[5m])))` | seconds |
| Detection rate | `rate(synapseids_detections_created_total{job="synapseids"}[5m])` | detections/s |
| Event delivery loss | `rate(synapseids_events_dropped_total{job="synapseids"}[5m])` | deliveries/s |

Do not sum `_all` together with individual `source` series: that doubles the
capture totals. Use `source!="_all"` when plotting individual sources. Keep
`instance` when comparing daemons. Counters reset on restart; use `rate` or
`increase`, not direct subtraction. A latency quantile can be absent/NaN when no
observations exist in the query window.

Capture metrics describe the capture manager's counters. Flow/feature-mode
sensors assemble flows before the daemon's packet path, so packet/byte counts
and live flow-table occupancy may differ from remote sensor or UI topology
counters. Replay is not a managed capture source. Classification counts and
sensor connectivity are useful cross-checks for those modes.

These metrics cover capture, flow tables, storage, inference, event delivery,
WebSocket clients, detections, and investigation aggregates. They do not import
OPNsense firewall allow/block counters or measure hidden-neuron activations.
Host CPU/RAM/GPU metrics require a host exporter; they are not claimed by this
endpoint.

The complete metric names and descriptions are in
[core metrics](../internal/api/metrics.go) and
[ML/sensor metrics](../internal/api/metrics_ml.go). Tests in
[internal/api/metrics_test.go](../internal/api/metrics_test.go) verify exposition
and recorded values; auth tests cover route roles.

Prometheus's [configuration reference](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
describes scrape jobs, authorization files, and TLS settings.


## Temporal neural workbench metrics

All series share the existing `/metrics` scrape endpoint. Fixed class/state labels bound cardinality; raw IPs, observed names and neuron IDs do not become labels.

| Series | Type | Meaning |
| --- | --- | --- |
| `synapseids_neural_threat_classifications_total{class}` | counter | Primary detailed threat classification events, across 19 fixed classes |
| `synapseids_neural_application_classifications_total{application}` | counter | Independent application classification events, across 14 fixed classes |
| `synapseids_behavior_inputs_total{coverage}` | counter | Rich or legacy input observations |
| `synapseids_training_worker_online` | gauge | 1 while an external worker has claimed/polled within 45 seconds |
| `synapseids_training_jobs{status}` | gauge | Queue/job history counts by lifecycle state |

An experimental threat shadow does not increment primary detailed-threat counters. An inactive application model produces no application classifications. Zero reflects that role's activity, not proof that no such traffic exists. Classification events include snapshots; do not label them unique sessions.

Examples:

```promql
sum by (class) (rate(synapseids_neural_threat_classifications_total[5m]))
sum by (application) (rate(synapseids_neural_application_classifications_total[5m]))
sum by (coverage) (rate(synapseids_behavior_inputs_total[5m]))
synapseids_training_worker_online
synapseids_training_jobs{status="queued"}
```

The worker also reports epochs, loss, validation accuracy/precision/recall/F1, learning rate, batches and elapsed seconds through the existing training series. The console retains every reported epoch; Prometheus samples at its scrape interval, so a very short training run can complete between two scrapes.
