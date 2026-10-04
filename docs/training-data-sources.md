# Training data sources and coverage

Training data quality determines what the model can learn. The output vocabulary
contains many classes; a model only supports classes represented by sufficient
labeled training examples. Treat the supplied starter as an experimental
comparison model and validate it against your own reviewed traffic.

## Prepared starter sources

| Source | What it contributes | Labeling / limitations |
| --- | --- | --- |
| [CTU-13](https://www.stratosphereips.org/datasets-ctu13), [capture source 46](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/) and [source 48](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/) | Historical Virut and Sogou infected-host traffic | Join official bidirectional flow labels by oriented tuple and capture time. Only `From-Botnet` is used as the coarse botnet-origin training label; that label does not prove every connection is malicious. |
| [CTU Normal 4, DNS only](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-4-only-DNS/) | Benign DNS examples | Narrow normal coverage; cannot represent normal enterprise traffic by itself. |
| [CTU Normal 13](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-13/) | A small benign browsing session | Useful as a normal example, too small for broad application evaluation. |
| [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures), `SkypeIRC.cap` | A small sample containing Skype, IRC and DNS traffic | Mixed capture. DNS/HTTP/TLS-on-443/plaintext IRC evidence is used for protocol examples; the whole file is never labeled IRC or Skype. Too few IRC examples exist to train that class. |

CTU attribution: Garcia, Sebastian, *Malware Capture Facility Project*,
[Stratosphere Laboratory](https://www.stratosphereips.org/). CTU-13 publication:
Garcia, Grill, Stiborek and Zunino, *An empirical comparison of botnet detection
methods*, Computers & Security 45 (2014), DOI
[10.1016/j.cose.2014.05.011](https://doi.org/10.1016/j.cose.2014.05.011).
Wireshark sample contributors are credited through the source page.

Raw PCAPs are kept in private local corpus storage and parsed offline. They are
not transmitted onto the monitored network, redistributed in this repository or
used as screenshots. No malware executables are downloaded or executed.
Prepared rows contain numeric features and hashed grouping identities, with
source/digest/label provenance. Preserve the original dataset attribution and
review its terms before redistribution.

## Datasets for expanding coverage

| Dataset | Relevant traffic | Acquisition considerations |
| --- | --- | --- |
| [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Scans, brute force, DoS/DDoS, botnet and web attacks alongside benign traffic | Large captures; join the published labels and check published labeling corrections. Reserve disk space before downloading. |
| [ISCX VPN/non-VPN](https://www.unb.ca/cic/datasets/vpn.html) | Older chat, browsing, email, streaming, file transfer and VoIP | The download site currently requests registration information. It does not establish coverage for every modern chat service. |
| [NIMS encrypted mobile instant messaging dataset](https://ieee-dataport.org/documents/encrypted-mobile-instant-messaging-traffic-dataset), DOI [10.21227/aer2-kq52](https://doi.org/10.21227/aer2-kq52) | Teams, WhatsApp, Signal and other labeled messaging captures | IEEE DataPort account/download access is required. Not included in the prepared starter. Preserve application/session boundaries and source license metadata. |
| Authorized local captures | Your application versions, network paths, ordinary administration and real false positives | Capture and label controlled sessions. Include inactive/background behavior and several devices/days. Avoid treating the capture filename or a destination port as conclusive ground truth. |

There is no validated Slack corpus in the starter. Teams, Slack, WhatsApp and
Signal remain unsupported until representative labeled captures are supplied.
A service's encryption is not bypassed: classification can learn timing and
metadata patterns, with uncertainty and evaluation appropriate to that evidence.

## Adding attack categories responsibly

Scans, host sweeps, individual flood types, RCE, phishing, malformed traffic and
DGA-like DNS require appropriate ground truth. A blocklist hit alone is not a
label for a particular exploit; an executable download is not necessarily
malware; a vulnerable service's port does not identify an RCE attempt. Use the
new detailed labels only when the source annotation or analyst review supports
that category. Maintain separate normal examples for the same protocols and
ports to reduce trivial shortcuts.

For mixed captures, prepare JSONL with the offline extractor and an appropriate
per-flow label join. Capture-wide labels in the web importer are intended for
verified single-label captures. Keep repeated conversations together and inspect
per-class support in each partition. Same-capture temporal evaluation should be
followed by independent-capture and independent-site tests before promotion.

## Maltrail-derived research and reputation

[Maltrail](https://github.com/stamparm/maltrail) informed the investigation of
bounded fan-out counters, DNS name shape/NXDOMAIN combinations and low-variance
connection intervals. SynapseIDS implements its own bounded calculations and
keeps those advisory signals separate from neural probabilities. No Maltrail
sensor or external feed plugin is executed inside SynapseIDS.

Shared feed sources include Spamhaus DROP and CINS Army. Optional AbuseIPDB and
explicit DNS RBL response-code mappings supply attributed, cached BadRep/RBL
evidence. Feed status, age and reason remain visible. These do not silently
relabel training examples or automatically block traffic. See
[Network policy](network-policy.md).
