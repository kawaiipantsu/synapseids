# Visual traffic workspace

The development preview opens on a redesigned Dashboard and keeps the existing
investigation routes. The committed `web/dist` bundle is embedded in Go builds;
`server.web_root` can serve a matching standalone build during development.

## Observe traffic

- **Dashboard:** traffic/classification rates, verdict distribution, observed
  processing stages, collection/delivery loss and an asset relationship graph.
  Rates require two samples; unavailable counters are not displayed as measured
  zeroes. Charts keep a short browser-session window.
- **Network graph:** force, ring and scope layouts; search, pan, zoom, reset,
  threat filtering, pause and asset selection. Inspect an asset's conversation
  totals and sampled ports, then open Investigate. Arrow direction represents
  initiator/responder observations, not router hops or proof of ownership.
- **Identity context:** cached reverse DNS and geolocation flags in live tables,
  model explanation, matrix and graph. Investigate shows geography, network ASN,
  WHOIS/RDAP allocation and cache age. See [IP context](ip-context.md) for setup,
  provider disclosure, cache limits and self-hosted geography.
- **Live inference:** follow the latest classified flow or pause on one. Select
  a model, view its actual recorded inputs/normalized inputs and output scores,
  and open the Flow Inspector. Registered layer widths produce the neural
  schematic; heuristic rules remain visibly distinct. Hidden-neuron values and
  connection weights are not available from the current runtime.

The graph is a bounded projection of the existing matrix API and recent-flow
port samples. It shows coverage/omission notices. Private/public address scope
does not establish local/remote asset ownership. DNS names are PTR context;
packet DNS query/answer relationships remain outside this API.

Firewall allow/block decisions are not imported. Capture loss, queue loss,
retention eviction and detection suppression are labeled independently.

## Train a classifier

1. Create or select a versioned dataset. Prefer human-reviewed labels;
   predicted labels can reproduce the current model's mistakes.
2. Open **Training**. Choose a dataset and a balanced, quick, anomaly or saved
   Architecture preset. Review the layer schematic and pinned 70/15/15 split.
3. Set the model name, epoch budget and learning rate. Download `dataset.csv`
   and `training-recipe.json` into the same worker directory.
4. Copy the displayed commands. Validate with `--dry-run`, then run the
   external Python trainer with `--report-to` pointing at the daemon.
5. When API authentication is enabled, supply an admin reporter token through
   `SYNAPSE_API_TOKEN` in the worker environment. The reporter refuses cross-origin
   progress URLs and HTTP redirects; credentials never enter the recipe.
6. Follow epoch loss and validation in the existing Training dashboard. Inspect
   the exported model's evaluation, register it, and explicitly activate it.

Anomaly training requires NORMAL examples and uses reconstruction loss. The UI
rejects invalid recipe values before download. Running a worker requires its
Python/PyTorch/ONNX dependencies; the daemon never launches Python or promotes
a bundle automatically.

## Monitor in Grafana

The existing `/metrics` scrape now includes training progress, runtime/registry
model counts, dataset inventory and remote sensor records in addition to traffic,
inference, detections, flow/storage, and delivery counters. Import the two
[Grafana dashboards](../contrib/grafana/README.md). See [Prometheus](prometheus.md)
for the scrape job, queries, units and limits.

## Operator documentation

The [product wiki](https://github.com/kawaiipantsu/synapseids/wiki) contains the
deployment and OPNsense guides, UI tour, investigation and training workflows,
API/CLI/configuration references, frozen feature reference, operations runbooks,
troubleshooting and a screenshot gallery. Public images use an isolated
synthetic dataset; untrained fixture results are labeled accordingly.

Some dedicated pages (Model Compare, Drift, Performance, Storage, Settings)
remain planned screens. The preview does not claim to implement their full
proposed workflows. Backend capabilities are documented separately.
