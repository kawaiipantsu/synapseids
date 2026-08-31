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
     * TODO(verify): Phalcon 4/5 (OPNsense 21.1 and later) ships
     * \Phalcon\Messages\Message; Phalcon 3 based releases used
     * \Phalcon\Validation\Message.  Confirm the Phalcon major version on the
     * target OPNsense release and adjust the `use` statement above if the
     * plugin must also build for a pre-21.1 core.
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

        // Cheap shape checks on the PEM blobs: catch a pasted DER blob or a
        // truncated copy/paste before the sensor fails to start.
        foreach (
            [
                'ca'          => gettext('The CA bundle does not look like PEM ("-----BEGIN ... -----" blocks).'),
                'client_cert' => gettext('The client certificate does not look like PEM.'),
                'client_key'  => gettext('The client private key does not look like PEM.'),
            ] as $field => $text
        ) {
            $value = $this->str($field);
            if ($value !== '' && strpos($value, '-----BEGIN') === false) {
                $this->addError($messages, 'general.' . $field, $text);
            }
        }

        return $messages;
    }
}
