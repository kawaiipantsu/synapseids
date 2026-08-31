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
 * Configuration model for the SynapseIDS distributed capture sensor
 * (`synapse-sensor pcap-over-ip`) running on this firewall.
 *
 * Per-field syntax is declared in Sensor.xml.  This class only adds the
 * *cross-field* rules that a single field cannot express, and mirrors the
 * refusals that the Go binary itself would make at start-up so the operator
 * gets them in the web UI instead of in a log file:
 *
 *   - live capture requires an explicit authorization assertion (PROJECT.md
 *     section 28.18 -- `--authorized` is mandatory whenever `--iface` is used);
 *   - `--connect` needs a collector address;
 *   - disabling peer verification (`--insecure-tls`) additionally requires the
 *     authorization assertion;
 *   - a missing bearer token means "accept any peer that completes the TLS
 *     handshake", which must be a conscious choice;
 *   - a client certificate and its private key are all-or-nothing
 *     (`--cert` and `--key` must be given together).
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
     * Cross-field validation, run on every save.
     *
     * @param bool $validateFullModel validate every node instead of only the changed ones
     * @return \Phalcon\Messages\Messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        $enabled     = $this->str('enabled') === '1';
        $authorized  = $this->str('authorized') === '1';
        $verifyPeer  = $this->str('verify_peer') === '1';
        $mode        = $this->str('mode');
        $interface   = $this->str('interface');
        $address     = $this->str('address');
        $token       = $this->str('token');
        $clientCert  = $this->str('client_cert');
        $clientKey   = $this->str('client_key');

        if ($enabled) {
            // PROJECT.md section 28.18 / section 21: capturing live traffic is an
            // authorization decision.  synapse-sensor refuses to start without
            // --authorized when --iface is set, so refuse it here first.
            if (!$authorized) {
                $this->addError(
                    $messages,
                    'general.authorized',
                    gettext(
                        'You must confirm that you are authorised to monitor the traffic on the selected ' .
                        'interface before the sensor can be enabled (PROJECT.md 28.18).'
                    )
                );
            }

            if ($interface === '') {
                $this->addError(
                    $messages,
                    'general.interface',
                    gettext('Select the interface to capture from; the sensor has no traffic source without it.')
                );
            }

            if ($mode === 'connect') {
                if ($address === '') {
                    $this->addError(
                        $messages,
                        'general.address',
                        gettext('In connect mode the address (host:port) of the SynapseIDS collector is required.')
                    );
                }

                // --insecure-tls is only accepted by the binary together with
                // --authorized; surface that here rather than at start-up.
                if (!$verifyPeer && !$authorized) {
                    $this->addError(
                        $messages,
                        'general.verify_peer',
                        gettext(
                            'Disabling collector certificate verification exposes the stream to interception. ' .
                            'Confirm the authorisation checkbox to accept that risk, or enable verification.'
                        )
                    );
                }
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

        // --cert and --key must be supplied together, enabled or not: half a key
        // pair is always a configuration mistake.
        // A comma means more than one interface is stored, which an earlier
        // release allowed (the field was a multi-select) while the configd
        // template only ever resolved the first identifier. On a live gateway
        // that meant WAN, IoT, DMZ and MGMT were selected and a single VLAN was
        // captured -- four segments believed monitored, one actually monitored,
        // and nothing anywhere reporting the difference.
        //
        // Not gated on "enabled": a stored multi-value is wrong either way, and
        // refusing it at save time is the only place the operator finds out
        // before trusting the coverage. Ungated so an existing configuration is
        // caught on the next save rather than silently carried forward.
        if (strpos($interface, ',') !== false) {
            $count = count(array_filter(explode(',', $interface), 'strlen'));
            $this->addError(
                $messages,
                'general.interface',
                sprintf(
                    gettext(
                        'Select exactly one interface. %d are stored (%s) but the sensor captures ' .
                        'a single device, so only the first would be monitored and the rest would be ' .
                        'silently ignored. Run one sensor per interface, or capture from a mirror ' .
                        'port that already carries the segments you want.'
                    ),
                    $count,
                    $interface
                )
            );
        }

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
