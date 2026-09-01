<?php

/*
 * Copyright (C) 2026 SynapseIDS contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\SynapseIDSSensor;

use OPNsense\Base\BaseModel;
use Phalcon\Messages\Message;

/**
 * Class Sensor
 *
 * Configuration model for the SynapseIDS distributed capture sensors
 * (`synapse-sensor pcap-over-ip`) running on this firewall: one process per
 * captured interface, sharing one transport and one set of secrets.
 *
 * Per-field syntax is declared in Sensor.xml.  This class only adds the
 * *cross-field* and *cross-instance* rules that a single field cannot express,
 * and mirrors the refusals that the Go binary itself would make at start-up so
 * the operator gets them in the web UI instead of in a log file:
 *
 *   - live capture requires an explicit authorization assertion, PER INSTANCE
 *     (PROJECT.md section 28.18 -- `--authorized` is mandatory whenever
 *     `--iface` is used, and authorisation for one segment is not authorisation
 *     for another);
 *   - `--connect` needs a collector address;
 *   - disabling peer verification (`--insecure-tls`) additionally requires the
 *     authorization assertion;
 *   - a missing bearer token means "accept any peer that completes the TLS
 *     handshake", which must be a conscious choice;
 *   - a client certificate and its private key are all-or-nothing
 *     (`--cert` and `--key` must be given together).
 *
 * The rules that only exist because there is now more than one sensor are all
 * uniqueness rules, and every one of them protects against a silently
 * unmonitored segment rather than against a cosmetic clash:
 *
 *   - two instances with the same NAME would render to the same configuration
 *     file, the same pidfile and the same log directory, so one of the two would
 *     simply never run;
 *   - two instances with the same LISTEN ADDRESS cannot both bind, so the second
 *     process to start dies with "address already in use";
 *   - two instances with the same SENSOR ID destroy the attribution that having
 *     one process per interface exists to provide;
 *   - two instances on the same INTERFACE double every flow on that segment.
 *
 * @package OPNsense\SynapseIDSSensor
 */
class Sensor extends BaseModel
{
    /**
     * Append a model level validation error.
     *
     * On the Phalcon class path: \Phalcon\Messages\Message is Phalcon 4/5, which
     * is every OPNsense from 21.1 onwards; \Phalcon\Validation\Message was
     * Phalcon 3, i.e. 21.1 and earlier.  This plugin targets the releases it is
     * packaged for — OPNsense 24.x/25.x, which are FreeBSD 14 (see
     * FREEBSD_VERSION in the top level Makefile and the pkg ABI in
     * scripts/package-opnsense.sh) — so \Phalcon\Messages\Message is correct and
     * the pre-21.1 case is deliberately not supported.  If it is wrong the page
     * throws a class-not-found on save, which is loud and immediate rather than
     * silent.
     *
     * @param \Phalcon\Messages\Messages $messages message collection to add to
     * @param string $key    model reference of the offending field, e.g. "general.token"
     * @param string $text   already translated, human readable explanation
     * @return void
     */
    private function addError($messages, string $key, string $text): void
    {
        $messages->appendMessage(new Message($text, $key));
    }

    /**
     * Read a leaf node as a trimmed string.
     *
     * @param string $path dotted path below <general>, e.g. "token"
     * @return string
     */
    private function str(string $path): string
    {
        $node = $this->general->$path;
        return $node === null ? '' : trim((string)$node);
    }

    /**
     * Read a leaf of an instance node as a trimmed string.
     *
     * @param mixed  $node instance node
     * @param string $name leaf name
     * @return string
     */
    private function inst($node, string $name): string
    {
        if (!isset($node->$name)) {
            return '';
        }
        $leaf = $node->$name;
        return $leaf === null ? '' : trim((string)$leaf);
    }

    /**
     * Model reference of an instance node, used as the message key so that the
     * grid dialog highlights the right field.  ApiMutableModelControllerBase
     * rewrites `instances.instance.<uuid>.x` to `instance.x` for a per-item
     * save and drops every message outside the node being edited, which is
     * exactly the behaviour wanted here.
     *
     * @param mixed  $node  instance node
     * @param string $field leaf name
     * @return string
     */
    private function ref($node, string $field): string
    {
        $reference = isset($node->__reference) ? (string)$node->__reference : 'instances.instance';
        return $reference . '.' . $field;
    }

    /**
     * Cross-field and cross-instance validation, run on every save.
     *
     * @param bool $validateFullModel validate every node instead of only the changed ones
     * @return \Phalcon\Messages\Messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        $enabled     = $this->str('enabled') === '1';
        $verifyPeer  = $this->str('verify_peer') === '1';
        $mode        = $this->str('mode');
        $address     = $this->str('address');
        $token       = $this->str('token');
        $clientCert  = $this->str('client_cert');
        $clientKey   = $this->str('client_key');

        $instances = [];
        foreach ($this->instances->instance->iterateItems() as $node) {
            $instances[] = $node;
        }
        $enabledInstances = [];
        foreach ($instances as $node) {
            if ($this->inst($node, 'enabled') === '1') {
                $enabledInstances[] = $node;
            }
        }

        if ($enabled) {
            if ($enabledInstances === []) {
                $this->addError(
                    $messages,
                    'general.enabled',
                    gettext(
                        'The plugin is enabled but no capture instance is. Add one sensor instance per ' .
                        'interface you want monitored, or turn the plugin off; a sensor with nothing to ' .
                        'capture reports healthy and monitors nothing.'
                    )
                );
            }

            if ($mode === 'connect' && $address === '') {
                $this->addError(
                    $messages,
                    'general.address',
                    gettext('In connect mode the address (host:port) of the SynapseIDS collector is required.')
                );
            }

            if ($token === '') {
                $this->addError(
                    $messages,
                    'general.token',
                    gettext(
                        'A bearer token is required: with an empty token the sensor accepts every peer that ' .
                        'completes the TLS handshake.'
                    )
                );
            }
        }

        // --insecure-tls is only accepted by the binary together with
        // --authorized; surface that here rather than at start-up. The
        // authorisation now lives on the instances, so this asks the question
        // the binary will ask of every process that is actually going to run.
        if ($enabled && $mode === 'connect' && !$verifyPeer) {
            foreach ($enabledInstances as $node) {
                if ($this->inst($node, 'authorized') !== '1') {
                    $this->addError(
                        $messages,
                        'general.verify_peer',
                        sprintf(
                            gettext(
                                'Disabling collector certificate verification exposes every stream to ' .
                                'interception, and instance "%s" has not confirmed authorisation. Tick the ' .
                                'authorisation box on each enabled instance to accept that risk, or enable ' .
                                'verification.'
                            ),
                            $this->inst($node, 'name')
                        )
                    );
                    break;
                }
            }
        }

        $this->validateInstances($messages, $instances, $mode);

        // NOTE for anyone diffing against #132: the "Select exactly one
        // interface" refusal that release added against `general.interface` is
        // gone from here, and deliberately. That field no longer describes a
        // capture -- it is a deprecated 1.0.0 leaf that Migrations\M1_0_1 reads
        // and blanks -- so a comma in it is a pre-migration artefact, not an
        // operator mistake, and erroring on it would block the first save after
        // an upgrade on a configuration nobody had touched. The rule it stood
        // for is now enforced where a capture is actually described:
        // validateInstances() refuses a comma in an *instance's* interface, and
        // the answer to wanting four segments is four instances.

        // --cert and --key must be supplied together, enabled or not: half a key
        // pair is always a configuration mistake.
        if ($clientCert !== '' && $clientKey === '') {
            $this->addError(
                $messages,
                'general.client_key',
                gettext('A client certificate was supplied without its private key.')
            );
        }
        if ($clientKey !== '' && $clientCert === '') {
            $this->addError(
                $messages,
                'general.client_cert',
                gettext('A client private key was supplied without its certificate.')
            );
        }

        // ------------------------------------------------------------------
        // TLS material (issue #104).
        //
        // Since the three PEM blobs are now rendered to disk by configd
        // templates rather than placed by hand, a blob that is not really PEM --
        // or a private key that does not parse -- would become a start-time or
        // handshake-time surprise on a firewall nobody logs into.  So it is a
        // configuration error here, at save time, in the web UI, where there is
        // a human to read it.
        //
        // The rc.d script still refuses to start when a referenced PEM is
        // missing, empty or has no BEGIN line, and `synapse-sensor doctor`
        // re-parses everything on the box.  This is the first of three barriers,
        // not the only one.
        // ------------------------------------------------------------------
        $this->validateCertificate($messages, 'client_cert', gettext('client certificate'));
        $this->validatePrivateKey($messages, 'client_key');
        $this->validateCABundle($messages, 'ca');
        $this->validateKeyPairMatches($messages, $clientCert, $clientKey);

        return $messages;
    }

    /**
     * Per-instance and cross-instance rules.
     *
     * Everything here exists to stop a segment being believed monitored while it
     * is not -- the failure that produced issue #124 in the first place.
     *
     * @param \Phalcon\Messages\Messages $messages
     * @param array                      $instances every instance node
     * @param string                     $mode      transport posture, listen or connect
     * @return void
     */
    private function validateInstances($messages, array $instances, string $mode): void
    {
        $seenNames = [];
        $seenIds = [];
        $seenListens = [];
        $seenIfaces = [];

        foreach ($instances as $node) {
            $name = $this->inst($node, 'name');
            $on = $this->inst($node, 'enabled') === '1';
            $iface = $this->inst($node, 'interface');
            $sensorId = $this->inst($node, 'sensor_id');
            $listen = $this->inst($node, 'listen_address');
            $label = $name !== '' ? $name : gettext('(unnamed)');

            // ---------------------------------------------------------- name
            if ($name !== '') {
                if (isset($seenNames[$name])) {
                    $this->addError($messages, $this->ref($node, 'name'), sprintf(
                        gettext(
                            'Another instance is already called "%s". The name is the service profile, the ' .
                            'configuration file, the pidfile and the log directory, so two instances sharing ' .
                            'one would leave a single sensor running and the other silently absent.'
                        ),
                        $name
                    ));
                }
                $seenNames[$name] = true;
            }

            // ----------------------------------------------------- interface
            // A comma means a stored multi-value: a pre-#132 release rendered a
            // multi-select here while the template used only the first
            // identifier. One interface per instance, one process per interface.
            if (strpos($iface, ',') !== false) {
                $this->addError($messages, $this->ref($node, 'interface'), sprintf(
                    gettext(
                        'Instance "%s" stores more than one interface (%s). One sensor process captures one ' .
                        'device: add a separate instance for each interface.'
                    ),
                    $label,
                    $iface
                ));
            } elseif ($iface !== '') {
                if (isset($seenIfaces[$iface])) {
                    $this->addError($messages, $this->ref($node, 'interface'), sprintf(
                        gettext(
                            'Instance "%s" captures %s, which instance "%s" already captures. Two sensors on ' .
                            'one interface report every flow on that segment twice.'
                        ),
                        $label,
                        $iface,
                        $seenIfaces[$iface]
                    ));
                }
                $seenIfaces[$iface] = $label;
            }

            // ----------------------------------------------------- sensor id
            if ($sensorId !== '') {
                if (isset($seenIds[$sensorId])) {
                    $this->addError($messages, $this->ref($node, 'sensor_id'), sprintf(
                        gettext(
                            'Sensor ID "%s" is already used by instance "%s". Running one process per ' .
                            'interface only gives correct attribution if each one reports a different ' .
                            'identity to the daemon.'
                        ),
                        $sensorId,
                        $seenIds[$sensorId]
                    ));
                }
                $seenIds[$sensorId] = $label;
            }

            if (!$on) {
                // A disabled instance is a record, not a running capture. Only
                // the uniqueness rules above apply to it, so that enabling it
                // later cannot silently collide with something.
                continue;
            }

            // ------------------------------------------- enabled instances --
            if ($iface === '') {
                $this->addError($messages, $this->ref($node, 'interface'), sprintf(
                    gettext(
                        'Instance "%s" is enabled but has no interface, so it has no traffic source at all.'
                    ),
                    $label
                ));
            }

            if ($sensorId === '') {
                $this->addError($messages, $this->ref($node, 'sensor_id'), sprintf(
                    gettext(
                        'Instance "%s" needs a sensor ID: it is how the daemon attributes the flows this ' .
                        'instance reports, and how you tell its capture apart from the other instances on ' .
                        'this firewall.'
                    ),
                    $label
                ));
            }

            // PROJECT.md section 28.18 / section 21. Per instance, and never
            // inherited: being authorised to monitor the WAN uplink says nothing
            // about being authorised to monitor a tenant VLAN.
            if ($this->inst($node, 'authorized') !== '1') {
                $this->addError($messages, $this->ref($node, 'authorized'), sprintf(
                    gettext(
                        'Confirm that you are authorised to monitor the traffic on the interface instance ' .
                        '"%s" captures before enabling it. Authorisation is per instance and is never ' .
                        'inherited from another one (PROJECT.md 28.18).'
                    ),
                    $label
                ));
            }

            // One-way capture invalidates the bidirectional feature set. When the
            // features are computed here on the sensor (`flow` / `feature` send
            // modes), a `direction` of `in` or `out` means the daemon scores a
            // flow-features-v1 vector whose reverse-direction half is
            // structurally zero. On a real gateway this produced `critical
            // dos_ddos` verdicts at 100% confidence on ordinary inbound reply
            // legs (issue #129). Raw mode is left to the operator's judgement --
            // the daemon at least sees the packets it is missing -- but on-sensor
            // feature computation from half-duplex capture is refused.
            $direction = $this->inst($node, 'direction');
            $sendMode  = $this->inst($node, 'send_mode');
            if (($direction === 'in' || $direction === 'out')
                && ($sendMode === 'flow' || $sendMode === 'feature')) {
                $this->addError($messages, $this->ref($node, 'direction'), sprintf(
                    gettext(
                        'Instance "%s" captures one direction only (%s) but builds flow %s on the sensor. ' .
                        'flow-features-v1 is a bidirectional feature set: with half the traffic missing, ' .
                        'every forward/backward ratio and all the reverse-direction counters are ' .
                        'structurally zero, and the daemon would score a vector it cannot trust. Capture ' .
                        'both directions, or send raw packets so the daemon can see what it is missing.'
                    ),
                    $label,
                    $direction === 'in' ? gettext('inbound only') : gettext('outbound only'),
                    $sendMode === 'feature' ? gettext('feature vectors') : gettext('records')
                ));
            }

            if ($mode !== 'listen') {
                continue;
            }

            // In listen mode every instance is its own TLS server, so each needs
            // its own port. Without this the second process to start dies with
            // "address already in use" and that segment goes unmonitored --
            // exactly the silent under-coverage this whole change is about.
            if ($listen === '') {
                $this->addError($messages, $this->ref($node, 'listen_address'), sprintf(
                    gettext(
                        'Instance "%s" needs its own listen address in listen mode, for example 0.0.0.0:4790. ' .
                        'Every instance is a separate process and they cannot share a port.'
                    ),
                    $label
                ));
                continue;
            }
            if (isset($seenListens[$listen])) {
                $this->addError($messages, $this->ref($node, 'listen_address'), sprintf(
                    gettext(
                        'Instance "%s" listens on %s, which instance "%s" already uses. Give each enabled ' .
                        'instance its own port, or only the first one to start will be listening.'
                    ),
                    $label,
                    $listen,
                    $seenListens[$listen]
                ));
            }
            $seenListens[$listen] = $label;
        }
    }

    /**
     * Split PEM text into its blocks and reject anything that is not a
     * well-formed, base64-decodable "-----BEGIN x----- ... -----END x-----".
     *
     * Catches the mistakes an operator actually makes in a textarea: a pasted
     * DER blob, a truncated copy, a missing END line, mismatched labels, or an
     * editor that mangled the base64.
     *
     * @param string $pem the pasted text
     * @return array{0: array<int, string>, 1: string} block labels, and an error or ''
     */
    private function pemBlocks(string $pem): array
    {
        $pem = str_replace(["\r\n", "\r"], "\n", trim($pem));
        if (strpos($pem, '-----BEGIN') === false) {
            return [[], gettext('does not look like PEM: no "-----BEGIN ..." line. ' .
                'Paste the text form, not a binary DER file.')];
        }

        $count = preg_match_all(
            '/-----BEGIN ([A-Z0-9 ]+)-----\R(.*?)\R?-----END \1-----/s',
            $pem,
            $matches,
            PREG_SET_ORDER
        );
        if ($count === false || $count === 0) {
            return [[], gettext('is not a complete PEM block: every "-----BEGIN x-----" needs a ' .
                'matching "-----END x-----" line.')];
        }

        // A trailing fragment means a block was cut off mid-paste.
        $beginCount = preg_match_all('/-----BEGIN /', $pem);
        if ($beginCount !== $count) {
            return [[], gettext('looks truncated: it has more "-----BEGIN" lines than complete blocks.')];
        }

        $labels = [];
        foreach ($matches as $match) {
            $body = preg_replace('/\s+/', '', $match[2]);
            if ($body === '' || base64_decode($body, true) === false) {
                return [[], sprintf(
                    gettext('has a "%s" block whose contents are not valid base64 -- the paste was ' .
                        'probably mangled by an editor.'),
                    $match[1]
                )];
            }
            $labels[] = $match[1];
        }
        return [$labels, ''];
    }

    /**
     * Validate a single X.509 certificate field.
     *
     * @param \Phalcon\Messages\Messages $messages
     * @param string $field model field below <general>
     * @param string $what  human name used in the message
     * @return void
     */
    private function validateCertificate($messages, string $field, string $what): void
    {
        $value = $this->str($field);
        if ($value === '') {
            return;
        }

        [$labels, $err] = $this->pemBlocks($value);
        if ($err !== '') {
            $this->addError($messages, 'general.' . $field, sprintf(gettext('The %s %s'), $what, $err));
            return;
        }
        foreach ($labels as $label) {
            if (strpos($label, 'PRIVATE KEY') !== false) {
                $this->addError($messages, 'general.' . $field, sprintf(
                    gettext('This is the %s field, but a "%s" block was pasted into it. ' .
                        'A private key here would be stored and rendered as a world-readable file -- ' .
                        'check you pasted into the right box.'),
                    $what,
                    $label
                ));
                return;
            }
            if ($label !== 'CERTIFICATE') {
                $this->addError($messages, 'general.' . $field, sprintf(
                    gettext('The %s must be a "CERTIFICATE" block; found "%s".'),
                    $what,
                    $label
                ));
                return;
            }
        }
        if (count($labels) > 1) {
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The %s must be a single certificate, not a chain of %d. ' .
                    'Put any intermediates in the CA field.'),
                $what,
                count($labels)
            ));
            return;
        }

        // openssl is a core OPNsense dependency (the Certificates page needs it),
        // but degrade to the shape check rather than fataling if it is absent.
        if (function_exists('openssl_x509_read') && @openssl_x509_read($value) === false) {
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The %s is PEM-shaped but OpenSSL cannot parse it as a certificate: %s'),
                $what,
                $this->opensslError()
            ));
        }
    }

    /**
     * Validate the private key field: PEM-shaped, actually a key, not
     * passphrase-protected, and parseable.
     *
     * @param \Phalcon\Messages\Messages $messages
     * @param string $field model field below <general>
     * @return void
     */
    private function validatePrivateKey($messages, string $field): void
    {
        $value = $this->str($field);
        if ($value === '') {
            return;
        }

        // Checked FIRST, on the raw text: a legacy PEM carries its "Proc-Type:
        // 4,ENCRYPTED" / "DEK-Info:" headers inside the block, so the base64
        // check below would otherwise reject it with a misleading "mangled
        // paste" message instead of telling the operator the real problem.
        //
        // Go's crypto/tls cannot use a passphrase-protected key, and an
        // unattended firewall has nowhere to type one. Refuse it here rather
        // than let the sensor fail at start-up on a box nobody is watching.
        if (
            strpos($value, '-----BEGIN ENCRYPTED PRIVATE KEY-----') !== false
            || strpos($value, 'Proc-Type: 4,ENCRYPTED') !== false
            || strpos($value, 'DEK-Info:') !== false
        ) {
            $this->addError($messages, 'general.' . $field, gettext(
                'The client private key is encrypted with a passphrase. The sensor runs ' .
                'unattended and cannot be prompted for one -- decrypt it first, for example ' .
                'with "openssl pkey -in key.pem -out plain.pem".'
            ));
            return;
        }

        [$labels, $err] = $this->pemBlocks($value);
        if ($err !== '') {
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The client private key %s'),
                $err
            ));
            return;
        }
        if (count($labels) !== 1) {
            $this->addError($messages, 'general.' . $field, gettext(
                'The client private key must be exactly one PEM block.'
            ));
            return;
        }
        if (strpos($labels[0], 'PRIVATE KEY') === false) {
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The client private key field holds a "%s" block, which is not a private key.'),
                $labels[0]
            ));
            return;
        }

        if (function_exists('openssl_pkey_get_private') && @openssl_pkey_get_private($value) === false) {
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The client private key is PEM-shaped but OpenSSL cannot parse it: %s'),
                $this->opensslError()
            ));
        }
    }

    /**
     * Validate the CA bundle: one or more certificates, nothing else.
     *
     * @param \Phalcon\Messages\Messages $messages
     * @param string $field model field below <general>
     * @return void
     */
    private function validateCABundle($messages, string $field): void
    {
        $value = $this->str($field);
        if ($value === '') {
            return;
        }

        [$labels, $err] = $this->pemBlocks($value);
        if ($err !== '') {
            $this->addError($messages, 'general.' . $field, sprintf(gettext('The CA bundle %s'), $err));
            return;
        }
        foreach ($labels as $label) {
            if ($label === 'CERTIFICATE') {
                continue;
            }
            $this->addError($messages, 'general.' . $field, sprintf(
                gettext('The CA bundle must contain only "CERTIFICATE" blocks; found "%s". ' .
                    'A private key in this field would be a serious mistake.'),
                $label
            ));
            return;
        }
    }

    /**
     * A certificate and a key that do not belong together is the mistake two
     * adjacent textareas invite, and it only shows up as a TLS handshake failure
     * on a remote firewall. Catch it at save time.
     *
     * @param \Phalcon\Messages\Messages $messages
     * @param string $cert certificate PEM
     * @param string $key  private key PEM
     * @return void
     */
    private function validateKeyPairMatches($messages, string $cert, string $key): void
    {
        if ($cert === '' || $key === '' || !function_exists('openssl_x509_check_private_key')) {
            return;
        }
        // Only meaningful once both halves parse on their own; the checks above
        // have already reported that case.
        if (@openssl_x509_read($cert) === false || @openssl_pkey_get_private($key) === false) {
            return;
        }
        if (!@openssl_x509_check_private_key($cert, $key)) {
            $this->addError($messages, 'general.client_key', gettext(
                'This private key does not match the client certificate above. The TLS ' .
                'handshake would fail every time the sensor connected.'
            ));
        }
    }

    /**
     * Drain OpenSSL's error queue into one short string for a message.
     *
     * @return string
     */
    private function opensslError(): string
    {
        $last = '';
        if (function_exists('openssl_error_string')) {
            while (($err = openssl_error_string()) !== false) {
                $last = $err;
            }
        }
        return $last === '' ? gettext('unknown error') : $last;
    }
}
