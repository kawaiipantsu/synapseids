# SynapseIDS Grafana dashboards

Import either JSON through Grafana **Dashboards → New → Import → Upload JSON**,
then select your Prometheus data source in the dashboard's **Data source**
selector. The default name is `db-prometheus`; no server address, data source
UID, credential, or observed host is embedded in these files.

- **synapseids-operations.json** — traffic/classification activity, detection
  policy, inference latency, sensor connections, flow/store pressure, loss,
  WebSocket delivery, scrape health and remote record throughput.
- **synapseids-neural-network.json** — reported training epochs, loss,
  validation accuracy/precision/recall/F1, reconstruction error, learning rate,
  worker freshness, dataset inventory, model parameters and live inference.

Both use built-in panels and Prometheus. They were API-validated on Grafana
13.2.3, and carry the portable classic dashboard JSON schema. Select a scrape
job, daemon, time range and (for training) run. Related-dashboard links retain
the time range. Stable UIDs are `synapseids-operations` and
`synapseids-neural-network`; import with a different UID if keeping an older
customized copy.

Configure the scraper using [the Prometheus guide](../../docs/prometheus.md).
No data is distinct from zero. Training gauges appear only after a worker
reports progress using `--report-to`; installing the dashboard does not start
a worker or activate a model. Scrapes sample wall time and cannot reconstruct
every epoch of a run that completed between scrapes. The console retains the
worker's reported epoch history.

Flow/feature-mode sensors export records and serialized record payload bytes.
That bandwidth measures sensor transport; it is not the original network's
packet bandwidth. Collection/queue/retention loss and firewall enforcement are
separate concepts. No firewall allow/block counts or hidden activations are
invented by these panels.

The JSON contains no alert rules, notification routes or contact points.

The Neural Network dashboard also includes a temporal-input coverage section,
independent application and detailed threat rates, workbench queue states and
worker heartbeat. These metrics count classification events; they are not live
accuracy measurements. Shadow threat output does not increment primary threat
counters. See [the neural workbench guide](../../docs/neural-workbench.md).
