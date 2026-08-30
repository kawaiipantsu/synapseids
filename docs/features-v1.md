# flow-features-v1 and traffic-classes-v1

The two frozen contracts the `flow-classifier-v1` model family is built on
(PROJECT.md §8, §9, §10). Source of truth:
`schemas/features/flow-features-v1.json` and
`schemas/outputs/traffic-classes-v1.json`, embedded into every binary and served
at `/api/v1/schemas/features` and `/api/v1/schemas/classes`.

> [!IMPORTANT]
> **This schema is frozen.** `input_size` is `48`, `"frozen": true`, and the
> order and meaning of every entry are permanent. A new measurement need creates
> **`flow-features-v2`** and a new model family **`flow-classifier-v2`** — the v1
> contract is never edited (PROJECT.md §8, §10, §28.5, §28.6).
>
> Enforcement: `internal/schema` `init()` panics if the feature count ≠
> `input_size`, if any `feature.index` ≠ its position, or if the class count ≠
> `output_size`. `internal/features` pins `Size = 48` (`TestVectorSizeMatchesSchema`).
> `schema.ValidateBundle` refuses any model bundle whose `feature_schema`,
> `input_size`, `output_schema` or `output_size` does not match this build,
> before it can run (PROJECT.md §9, §11).

## flow-features-v1

Computed by `features.Extract(flow.Record)` entirely from **one bidirectional
flow record**. No raw IP addresses enter the vector — only derived behavioural
and context values (PROJECT.md §8). `default_missing` is `0.0`. After all 48
slots are filled, `Extract` replaces any `NaN`/`±Inf` with `0` as a final pass.

`norm` legend: `identity` = passthrough · `log1p` = `log(1+x)` (deterministic,
no fitted parameters; `features.Log1p` applies it to exactly the `log1p` rows) ·
`standard` = z-score, **parameters supplied by a trained model's
`normalizer.json`** — Phase 1 has none, and the `Heuristic` model reads raw
values regardless (PROJECT.md §11).

| # | name | type | unit | calc | missing | norm |
|--:|---|---|---|---|---|---|
| 0 | `flow_duration` | float | seconds | `last_seen - first_seen` | 0 for a single-packet flow | log1p |
| 1 | `packets_forward` | float | count | packet count initiator→responder | 0 | log1p |
| 2 | `packets_backward` | float | count | packet count responder→initiator | 0 | log1p |
| 3 | `bytes_forward` | float | bytes | sum of IP datagram lengths forward (IP header included) | 0 | log1p |
| 4 | `bytes_backward` | float | bytes | sum of IP datagram lengths backward (IP header included) | 0 | log1p |
| 5 | `packet_size_mean` | float | bytes | mean total packet size over the flow | 0 | standard |
| 6 | `packet_size_min` | float | bytes | min total packet size | 0 | standard |
| 7 | `packet_size_max` | float | bytes | max total packet size | 0 | standard |
| 8 | `packet_size_stddev` | float | bytes | population stddev of packet size | 0 for <2 packets | standard |
| 9 | `forward_packet_size_mean` | float | bytes | mean packet size forward | 0 | standard |
| 10 | `backward_packet_size_mean` | float | bytes | mean packet size backward | 0 | standard |
| 11 | `packets_per_second` | float | 1/s | `total_packets / max(flow_duration, 1e-6)` | total packets when duration is 0 | log1p |
| 12 | `bytes_per_second` | float | bytes/s | `total_bytes / max(flow_duration, 1e-6)` | total bytes when duration is 0 | log1p |
| 13 | `forward_packets_per_second` | float | 1/s | `packets_forward / max(flow_duration, 1e-6)` | packets_forward when duration is 0 | log1p |
| 14 | `backward_packets_per_second` | float | 1/s | `packets_backward / max(flow_duration, 1e-6)` | packets_backward when duration is 0 | log1p |
| 15 | `interarrival_mean` | float | seconds | mean inter-arrival gap over all packets | 0 for <2 packets | log1p |
| 16 | `interarrival_min` | float | seconds | min inter-arrival gap | 0 for <2 packets | log1p |
| 17 | `interarrival_max` | float | seconds | max inter-arrival gap | 0 for <2 packets | log1p |
| 18 | `interarrival_stddev` | float | seconds | population stddev of inter-arrival gaps | 0 for <3 packets | log1p |
| 19 | `forward_interarrival_mean` | float | seconds | mean forward inter-arrival gap | 0 for <2 forward packets | log1p |
| 20 | `backward_interarrival_mean` | float | seconds | mean backward inter-arrival gap | 0 for <2 backward packets | log1p |
| 21 | `source_port` | float | port | initiator L4 port (0 for ICMP) | 0 | identity |
| 22 | `destination_port` | float | port | responder L4 port (0 for ICMP) | 0 | identity |
| 23 | `protocol_tcp` | bool | flag | 1 if transport is TCP | 0 | identity |
| 24 | `protocol_udp` | bool | flag | 1 if transport is UDP | 0 | identity |
| 25 | `protocol_icmp` | bool | flag | 1 if transport is ICMPv4/ICMPv6 | 0 | identity |
| 26 | `tcp_syn_count` | float | count | packets with SYN set | 0 | log1p |
| 27 | `tcp_ack_count` | float | count | packets with ACK set | 0 | log1p |
| 28 | `tcp_fin_count` | float | count | packets with FIN set | 0 | log1p |
| 29 | `tcp_rst_count` | float | count | packets with RST set | 0 | log1p |
| 30 | `tcp_psh_count` | float | count | packets with PSH set | 0 | log1p |
| 31 | `tcp_urg_count` | float | count | packets with URG set | 0 | log1p |
| 32 | `syn_ack_ratio` | float | ratio | `tcp_syn_count / max(tcp_ack_count, 1)` | tcp_syn_count when ack is 0 | log1p |
| 33 | `packet_direction_ratio` | float | ratio | `packets_forward / max(total_packets, 1)` | 0 | identity |
| 34 | `byte_direction_ratio` | float | ratio | `bytes_forward / max(total_bytes, 1)` | 0 | identity |
| 35 | `initial_tcp_window` | float | bytes | TCP window of the first forward segment | 0 for non-TCP | standard |
| 36 | `average_tcp_window` | float | bytes | mean advertised TCP window over the flow | 0 for non-TCP | standard |
| 37 | `down_up_bytes_ratio` | float | ratio | `bytes_backward / max(bytes_forward, 1)` | 0 | log1p |
| 38 | `small_packet_ratio` | float | ratio | fraction of packets ≤ 100 bytes total | 0 | identity |
| 39 | `large_packet_ratio` | float | ratio | fraction of packets ≥ 1000 bytes total | 0 | identity |
| 40 | `average_payload_length` | float | bytes | mean L4 payload length over all packets | 0 | standard |
| 41 | `bidirectional_flag` | bool | flag | 1 if both directions carried ≥1 packet | 0 | identity |
| 42 | `internal_to_internal` | bool | flag | 1 if both endpoints are RFC1918 / ULA / link-local | 0 | identity |
| 43 | `internal_to_external` | bool | flag | 1 if initiator internal, responder external | 0 | identity |
| 44 | `external_to_internal` | bool | flag | 1 if initiator external, responder internal | 0 | identity |
| 45 | `external_to_external` | bool | flag | 1 if neither endpoint is internal | 0 | identity |
| 46 | `dest_port_is_wellknown` | bool | flag | 1 if `destination_port` in [1, 1023] | 0 | identity |
| 47 | `snapshot_index` | float | count | nth periodic snapshot of a long-lived flow; 0 on close | 0 | identity |

**Implementation note.** `bytes_forward` / `bytes_backward` (#3, #4) and every
`packet_size_*` feature (#5–#10) are accumulated from `packet.TotalLen` — the
**full IP datagram length**, IP header included, not the L4 payload. Only
`average_payload_length` (#40) uses true L4 payload lengths. `internal` for the
context flags (#42–#45) means private, loopback or link-local
(`netip.Addr.IsPrivate|IsLoopback|IsLinkLocal*`).

## traffic-classes-v1

`output_size` is `7`, `"frozen": true`. The class count and ordering are locked
for every model in `flow-classifier-v1` (PROJECT.md §9).

| id | name | description |
|--:|---|---|
| 0 | `normal` | Benign traffic. |
| 1 | `scan` | Host / port / service discovery. |
| 2 | `dos_ddos` | Denial-of-service or distributed denial-of-service. |
| 3 | `brute_force` | Credential brute force against a service. |
| 4 | `botnet_c2` | Botnet command-and-control channel. |
| 5 | `web_attack` | Web application attack (injection, traversal, RCE attempt). |
| 6 | `suspicious` | Anomalous but unattributed. |

> `suspicious` is a **supervised class**, not an anomaly score (PROJECT.md §9,
> §13). It is a catch-all the model is trained to predict — not a novelty or
> reconstruction-error signal. Real anomaly/novelty detection is a **separate
> model** (an autoencoder), producing its own score alongside these class
> probabilities. That model has role `anomaly` in `inference.Runtime` and is
> excluded from the disagreement check; it lands in Phase 7.

The Phase-1 `Heuristic` (`internal/inference/heuristic.go`) emits a real
softmax over these 7 classes. It is deliberately conservative: a flow that trips
no rule reads as `normal`, and a weak signal lands on `suspicious` rather than
being forced into an attack class because softmax always has a maximum
(PROJECT.md §13).

## Features deferred to v2

PROJECT.md §8 lists ~56 candidate features; v1 froze 48. Everything below was
left out of v1 because it cannot be computed from a single flow record:

| Candidate (PROJECT.md §8) | Why not in v1 |
|---|---|
| `source_unique_dst_ports_1s`, `source_unique_dst_ports_10s` | need a **host tracker** — a per-source sliding-window aggregator over *all* flows |
| `source_unique_dst_hosts_1s`, `source_unique_dst_hosts_10s` | same |
| `source_connections_1s`, `source_connections_10s` | same |
| `source_failed_connection_ratio` | same, plus connection-outcome bookkeeping |
| `source_activity_score` | composite host metric derived from the above |
| `destination_port_rarity` | needs an observed/learned port-frequency table |
| `retransmission_count`, `duplicate_ack_count` | need per-flow TCP sequence/ACK state, which `flow.Table` does not keep |
| `payload_entropy` | the decoder discards payload bytes — `packet.Packet` carries only `PayloadLen`, never the bytes |

The cross-flow host-context features are the main reason for a `flow-features-v2`:
they require an `internal/hosts` tracker that maintains sliding-window
per-source state. The frozen v1 description says so explicitly — *"no cross-flow
host state (that is reserved for a future flow-features-v2)"*. Adding them means a
new schema version and a new model family, never a change to v1.

v1 also **added** four features not in the §8 list: `down_up_bytes_ratio` (37),
`external_to_external` (45), `dest_port_is_wellknown` (46) and `snapshot_index`
(47).

## The golden test guards the schema

`internal/features/golden_test.go` freezes the exact output of feature
extraction against committed fixtures (PROJECT.md §25):

- **Fixtures** — `testdata/pcap/{http,portscan,udp}.pcap`, themselves generated
  by `go run ./testdata/gen` (generator committed alongside output; CI fails if
  `testdata/pcap` is stale).
- **Goldens** — `internal/features/testdata/{http,portscan,udp}.pcap.golden.json`,
  one JSON array of `Vector`s per fixture, sorted by initiator port for
  stability. `flow_id` is zeroed — it is not part of the contract.
- **Run it** — `go test ./internal/features -run TestGolden`. The test replays
  each fixture through `capture → flow → features` and byte-compares the
  marshalled JSON to the golden file. Any drift in a feature calculation fails
  the test with a diff.
- **Regenerate deliberately** —
  `go test ./internal/features -run TestGolden -update` rewrites the goldens. Do
  this only with a reviewed calc fix or a schema-version bump; CI never passes
  `-update`.

Alongside it, `TestVectorSizeMatchesSchema` asserts `features.Size == 48` and the
`schema` package's `init()` cross-checks the embedded JSON on every startup.

---

⟦THUGS⟧ (c) 2026
