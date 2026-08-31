<?php

/*
 * Exercise Sensor::performValidation outside an OPNsense MVC runtime.
 *
 * Copyright (C) 2026 SynapseIDS contributors
 * BSD 2-Clause; see Sensor.php for the full text.
 *
 * A development aid, not part of the package (deliberately absent from
 * pkg-plist).  `php -l` only proves the file parses; this proves the
 * cross-field and PEM rules actually fire, which matters because the model is
 * the first of the three barriers standing between a mistyped certificate and a
 * firewall that refuses to start (the others are the rc.d start_precmd and
 * `synapse-sensor doctor`).
 *
 * BaseModel and Phalcon are stubbed with the smallest surface Sensor.php uses:
 * a `general` node of stringable leaves, and a message collection.
 *
 *     php contrib/opnsense/tools/test-sensor-model.php
 *
 * Exit status is non-zero if any case behaves unexpectedly.
 */

declare(strict_types=1);

namespace {
    if (!extension_loaded('openssl')) {
        fwrite(STDERR, "test-sensor-model: the openssl extension is required\n");
        exit(77);
    }
}

// ------------------------------------------------------------------ stubs

namespace Phalcon\Messages {
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = null)
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }

    class Messages implements \IteratorAggregate, \Countable
    {
        private $items = [];

        public function appendMessage($message)
        {
            $this->items[] = $message;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->items);
        }

        public function count(): int
        {
            return count($this->items);
        }
    }
}

namespace OPNsense\Base {
    class Leaf
    {
        private $value;

        public function __construct($value)
        {
            $this->value = $value;
        }

        public function __toString(): string
        {
            return (string)$this->value;
        }
    }

    class Node
    {
        public function __construct(array $values)
        {
            foreach ($values as $k => $v) {
                $this->$k = new Leaf($v);
            }
        }
    }

    class BaseModel
    {
        public $general;

        public function performValidation($validateFullModel = false)
        {
            return new \Phalcon\Messages\Messages();
        }
    }
}

// ------------------------------------------------------------------ harness

namespace {
    if (!function_exists('gettext')) {
        function gettext($s)
        {
            return $s;
        }
    }

    require __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor/Sensor.php';

    /** Generate a real key pair so the tests are not built on hand-written PEM. */
    function makePair(string $cn): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => $cn], $key, ['digest_alg' => 'sha256']);
        $crt = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);
        openssl_x509_export($crt, $certPem);
        openssl_pkey_export($key, $keyPem);
        return [$certPem, $keyPem];
    }

    function defaults(): array
    {
        return [
            'enabled'        => '1',
            'authorized'     => '1',
            'verify_peer'    => '1',
            'mode'           => 'listen',
            'interface'      => 'wan',
            'address'        => '',
            'listen_address' => '0.0.0.0:4789',
            'token'          => 'a-bearer-token',
            'sensor_id'      => 'opnsense-wan',
            'location'       => '',
            'ca'             => '',
            'client_cert'    => '',
            'client_key'     => '',
        ];
    }

    /** @return string[] the field names that produced an error */
    function validate(array $overrides): array
    {
        $model = new \OPNsense\SynapseIDSSensor\Sensor();
        $model->general = new \OPNsense\Base\Node(array_merge(defaults(), $overrides));
        $fields = [];
        foreach ($model->performValidation(true) as $msg) {
            $fields[] = $msg->getField() . ': ' . $msg->getMessage();
        }
        return $fields;
    }

    $failures = 0;
    $ran = 0;

    /**
     * @param string   $name     scenario name
     * @param array    $override model fields to set
     * @param string[] $wantKeys substrings that must appear among the errors
     * @param bool     $wantNone assert there are no errors at all
     */
    function check(string $name, array $override, array $wantKeys = [], bool $wantNone = false): void
    {
        global $failures, $ran;
        $ran++;
        $errors = validate($override);
        $joined = implode("\n", $errors);

        if ($wantNone) {
            if ($errors !== []) {
                $failures++;
                printf("FAIL  %s: expected no errors, got:\n      %s\n", $name, str_replace("\n", "\n      ", $joined));
                return;
            }
            printf("ok    %s (no errors)\n", $name);
            return;
        }

        $missing = [];
        foreach ($wantKeys as $needle) {
            if (stripos($joined, $needle) === false) {
                $missing[] = $needle;
            }
        }
        if ($missing !== []) {
            $failures++;
            printf(
                "FAIL  %s: missing %s in:\n      %s\n",
                $name,
                json_encode($missing),
                $joined === '' ? '(no errors at all)' : str_replace("\n", "\n      ", $joined)
            );
            return;
        }
        printf("ok    %s (%d error(s))\n", $name, count($errors));
    }

    [$certA, $keyA] = makePair('sensor-a.example');
    [$certB, $keyB] = makePair('sensor-b.example');

    // ---------------------------------------------------------- happy paths

    check('valid listen-mode sensor, no TLS material', [], [], true);
    check('valid mTLS pair', ['client_cert' => $certA, 'client_key' => $keyA], [], true);
    check('valid CA bundle', ['ca' => $certA], [], true);
    check('valid CA chain of two', ['ca' => $certA . "\n" . $certB], [], true);
    check('disabled sensor skips the enabled-only rules', [
        'enabled' => '0', 'authorized' => '0', 'interface' => '', 'token' => '',
    ], [], true);
    check('CRLF pasted from a Windows editor', [
        'client_cert' => str_replace("\n", "\r\n", $certA),
        'client_key'  => str_replace("\n", "\r\n", $keyA),
    ], [], true);
    check('valid connect mode', [
        'mode' => 'connect', 'address' => 'ids.example.net:4789',
    ], [], true);

    // ------------------------------------------------- pre-existing rules

    check('enabled without authorised', ['authorized' => '0'], ['general.authorized', '28.18']);
    check('enabled without an interface', ['interface' => ''], ['general.interface']);
    check('enabled without a token', ['token' => ''], ['general.token']);
    check('connect mode without an address', ['mode' => 'connect'], ['general.address']);
    check('insecure TLS without authorisation', [
        'mode' => 'connect', 'address' => 'x:1', 'verify_peer' => '0', 'authorized' => '0',
    ], ['general.verify_peer']);
    check('certificate without a key', ['client_cert' => $certA], ['general.client_key']);
    check('key without a certificate', ['client_key' => $keyA], ['general.client_cert']);

    // ------------------------------------------------------ PEM validation

    check('DER blob pasted into the certificate field', [
        'client_cert' => "\x30\x82\x01\x0a binary junk", 'client_key' => $keyA,
    ], ['general.client_cert', 'does not look like PEM']);

    check('truncated certificate', [
        'client_cert' => substr($certA, 0, (int)(strlen($certA) / 2)), 'client_key' => $keyA,
    ], ['general.client_cert']);

    check('missing END line', [
        'client_cert' => str_replace('-----END CERTIFICATE-----', '', $certA), 'client_key' => $keyA,
    ], ['general.client_cert', 'complete PEM block']);

    check('mangled base64 body', [
        'client_cert' => preg_replace('/^[A-Za-z0-9+\/=]{20}/m', 'not base64 !!!! ', $certA),
        'client_key'  => $keyA,
    ], ['general.client_cert']);

    check('private key pasted into the certificate field', [
        'client_cert' => $keyA, 'client_key' => $keyA,
    ], ['general.client_cert', 'private key here']);

    check('private key pasted into the CA field', [
        'ca' => $keyA,
    ], ['general.ca', 'serious mistake']);

    check('certificate pasted into the key field', [
        'client_cert' => $certA, 'client_key' => $certA,
    ], ['general.client_key', 'not a private key']);

    check('a chain in the certificate field', [
        'client_cert' => $certA . "\n" . $certB, 'client_key' => $keyA,
    ], ['general.client_cert', 'single certificate']);

    check('mismatched certificate and key', [
        'client_cert' => $certA, 'client_key' => $keyB,
    ], ['general.client_key', 'does not match']);

    // An encrypted key: Go's crypto/tls cannot use one and there is nobody to
    // type the passphrase on an unattended firewall.
    $encKey = '';
    openssl_pkey_export(
        openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']),
        $encKey,
        'a-passphrase'
    );
    check('passphrase-protected private key', [
        'client_cert' => $certA, 'client_key' => $encKey,
    ], ['general.client_key', 'encrypted with a passphrase']);

    check('legacy Proc-Type encrypted key header', [
        'client_cert' => $certA,
        'client_key'  => "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n" .
            "DEK-Info: AES-128-CBC,0123\n\nQUJDRA==\n-----END RSA PRIVATE KEY-----",
    ], ['general.client_key', 'encrypted with a passphrase']);

    printf("\n%d/%d cases passed\n", $ran - $failures, $ran);
    exit($failures === 0 ? 0 : 1);
}
