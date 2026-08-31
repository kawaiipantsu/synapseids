# PCAP-over-IP capture source

`synapse.pcap-over-ip.json` is a `synapsed` config with one `kind: "pcap-over-ip"`
capture source. It consumes a framed, authenticated TLS stream (the **SYNPOIP**
protocol — see `internal/capture/pcapoverip/PROTOCOL.md` and
`docs/adr/0012-pcap-over-ip-transport.md`) from a remote sensor.

## Source fields

| field                              | meaning                                                                 |
|------------------------------------|-----------------------------------------------------------------------|
| `addr` (required)                  | sensor `host:port`                                                    |
| `token_file`                       | path to a file holding the bearer token. **Never** put the token inline (`token` is refused, PROJECT.md §23). Alternatively set `SYNAPSE_POIP_TOKEN` in the environment. |
| `server_name`                      | TLS SNI / certificate name to verify (default: the host part of `addr`) |
| `ca_file`                          | PEM bundle that verifies the sensor certificate. Omit to use the host's system roots. |
| `client_cert_file` + `client_key_file` | present a client certificate for **mutual TLS** (both or neither)  |
| `insecure_tls`                     | skip sensor certificate verification. Logs a loud warning; requires `authorized: true`. |
| `authorized`                       | the operator asserting they are authorized to monitor `addr` (PROJECT.md §21) and accepting any `insecure_tls` / token-less choice (§28.18). **Required** for a non-loopback `addr`, for `insecure_tls`, or when no token is configured. |

A `pcap-over-ip` source does not reconnect on its own yet: a dropped stream shows
`state: "error"` in `GET /api/v1/captures` until `synapsed` is restarted.

## Generating a certificate for a sensor

The reference server (`synapse-sensor pcap-over-ip`) generates and fingerprints
an in-memory self-signed certificate when `--cert` / `--key` are omitted — fine
for a lab. For anything else, provision a real key pair. A self-signed pair with
OpenSSL:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout sensor-key.pem -out sensor-cert.pem -days 365 -nodes \
  -subj "/CN=hq-sensor.internal" \
  -addext "subjectAltName=DNS:hq-sensor.internal,IP:10.20.0.9"

# run the sensor with it
synapse-sensor pcap-over-ip --listen :4789 --from ./capture.pcap \
  --token-file ./pcap-over-ip.token --cert sensor-cert.pem --key sensor-key.pem

# on the daemon host: pin the sensor's certificate as the CA
cp sensor-cert.pem /etc/synapseids/hq-sensor-ca.pem
```

For mutual TLS, generate a second key pair for the daemon, give the sensor
`--client-ca <daemon-cert.pem>`, and point the source at
`client_cert_file` / `client_key_file`.

The bearer token is any high-entropy string; keep the file `0600` and owned by
the `synapseids` user:

```bash
head -c 32 /dev/urandom | base64 > /etc/synapseids/pcap-over-ip.token
chmod 600 /etc/synapseids/pcap-over-ip.token
```
