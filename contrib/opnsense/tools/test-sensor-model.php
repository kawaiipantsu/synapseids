<?php

/*
 * Exercise Sensor::performValidation and Migrations\M1_0_1 outside an OPNsense
 * MVC runtime.
 *
 * Copyright (C) 2026 SynapseIDS contributors
 * BSD 2-Clause; see Sensor.php for the full text.
 *
 * A development aid, not part of the package (deliberately absent from
 * pkg-plist).  `php -l` only proves the files parse; this proves the
 * cross-field, cross-instance and migration rules actually fire, which matters
 * because the model is the first of the three barriers standing between a
 * mistyped configuration and a firewall that captures nothing (the others are
 * the rc.d start_precmd and `synapse-sensor doctor`).
 *
 * BaseModel, BaseModelMigration, ArrayField and Phalcon are stubbed with the
 * smallest surface the plugin uses: a `general` node of stringable leaves, a
 * repeating `instances.instance` node with iterateItems()/add(), and a message
 * collection.
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

    /**
     * One item of a repeating node. The real thing exposes __reference as the
     * dotted model path of the item ("instances.instance.<uuid>"), which is what
     * ApiMutableModelControllerBase::validate() matches validation messages
     * against, so the stub has to carry it too.
     */
    class Item extends Node
    {
        public $__reference;

        public function __construct(array $values, string $reference)
        {
            parent::__construct($values);
            $this->__reference = $reference;
        }
    }

    /**
     * Stand-in for OPNsense\Base\FieldTypes\ArrayField.
     *
     * Only iterateItems() and add() are needed: the model reads the list and the
     * migration appends to it.
     */
    class ArrayFieldStub
    {
        private $items = [];
        private $defaults;
        private $path;
        private $seq = 0;

        public function __construct(string $path, array $defaults)
        {
            $this->path = $path;
            $this->defaults = $defaults;
        }

        public function iterateItems()
        {
            return $this->items;
        }

        public function add($uuid = null)
        {
            $this->seq++;
            $item = new Item($this->defaults, $this->path . '.uuid-' . $this->seq);
            $this->items[] = $item;
            return $item;
        }

        public function append(array $values)
        {
            $item = $this->add();
            foreach ($values as $k => $v) {
                $item->$k = new Leaf($v);
            }
            return $item;
        }

        public function count(): int
        {
            return count($this->items);
        }
    }

    class Container
    {
        public $instance;

        public function __construct(ArrayFieldStub $instance)
        {
            $this->instance = $instance;
        }
    }

    class BaseModel
    {
        public $general;
        public $instances;

        public function performValidation($validateFullModel = false)
        {
            return new \Phalcon\Messages\Messages();
        }
    }

    /**
     * The real BaseModelMigration::run() only walks the tree applying defaults
     * to required fields that are unset, which the stub model does not model at
     * all -- every field here is always set. So the parent is a no-op and what
     * is exercised below is M1_0_1's own logic, which is the part that can lose
     * an operator's configuration.
     */
    class BaseModelMigration
    {
        public function run($model)
        {
        }

        public function post($model)
        {
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
    require __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/SynapseIDSSensor/Migrations/M1_0_1.php';

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

    /** The shared settings, as saved by the settings form. */
    function defaults(): array
    {
        return [
            'enabled'     => '1',
            'mode'        => 'listen',
            'address'     => '',
            'token'       => 'a-bearer-token',
            'verify_peer' => '1',
            'ca'          => '',
            'client_cert' => '',
            'client_key'  => '',
            // The deprecated 1.0.0 leaves, blanked by the migration.
            'interface'      => '',
            'filter'         => '',
            'direction'      => '',
            'promiscuous'    => '',
            'snaplen'        => '',
            'send_mode'      => '',
            'listen_address' => '',
            'sensor_id'      => '',
            'location'       => '',
            'authorized'     => '',
        ];
    }

    /** One capture instance, as saved by the grid dialog. */
    function inst(string $name, array $overrides = []): array
    {
        return array_merge([
            'enabled'        => '1',
            'name'           => $name,
            'interface'      => $name,
            'listen_address' => '0.0.0.0:4789',
            'filter'         => 'ip-any',
            'direction'      => 'in',
            'promiscuous'    => '1',
            'snaplen'        => '262144',
            'send_mode'      => 'raw',
            'sensor_id'      => 'opnsense-' . $name,
            'location'       => 'edge',
            'authorized'     => '1',
            'description'    => '',
        ], $overrides);
    }

    function newModel(array $generalOverrides = [], array $instances = []): \OPNsense\SynapseIDSSensor\Sensor
    {
        $model = new \OPNsense\SynapseIDSSensor\Sensor();
        $model->general = new \OPNsense\Base\Node(array_merge(defaults(), $generalOverrides));
        $array = new \OPNsense\Base\ArrayFieldStub('instances.instance', inst(''));
        foreach ($instances as $values) {
            $array->append($values);
        }
        $model->instances = new \OPNsense\Base\Container($array);
        return $model;
    }

    /** @return string[] the "field: message" pairs the model produced */
    function validate(array $overrides, array $instances = null): array
    {
        if ($instances === null) {
            $instances = [inst('wan')];
        }
        $model = newModel($overrides, $instances);
        $fields = [];
        foreach ($model->performValidation(true) as $msg) {
            $fields[] = $msg->getField() . ': ' . $msg->getMessage();
        }
        return $fields;
    }

    $failures = 0;
    $ran = 0;

    /**
     * @param string     $name      scenario name
     * @param array      $override  general fields to set
     * @param string[]   $wantKeys  substrings that must appear among the errors
     * @param bool       $wantNone  assert there are no errors at all
     * @param array|null $instances instance list, or null for one valid WAN sensor
     */
    function check(
        string $name,
        array $override,
        array $wantKeys = [],
        bool $wantNone = false,
        array $instances = null
    ): void {
        global $failures, $ran;
        $ran++;
        $errors = validate($override, $instances);
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

    /** Assert an arbitrary condition, for the migration cases. */
    function assertThat(string $name, bool $ok, string $detail = ''): void
    {
        global $failures, $ran;
        $ran++;
        if ($ok) {
            printf("ok    %s\n", $name);
            return;
        }
        $failures++;
        printf("FAIL  %s%s\n", $name, $detail === '' ? '' : ': ' . $detail);
    }

    [$certA, $keyA] = makePair('sensor-a.example');
    [$certB, $keyB] = makePair('sensor-b.example');

    // ---------------------------------------------------------- happy paths

    check('valid listen-mode sensor, no TLS material', [], [], true);
    check('valid mTLS pair', ['client_cert' => $certA, 'client_key' => $keyA], [], true);
    check('valid CA bundle', ['ca' => $certA], [], true);
    check('valid CA chain of two', ['ca' => $certA . "\n" . $certB], [], true);
    check('plugin disabled skips the enabled-only rules', [
        'enabled' => '0', 'token' => '',
    ], [], true, []);
    check('CRLF pasted from a Windows editor', [
        'client_cert' => str_replace("\n", "\r\n", $certA),
        'client_key'  => str_replace("\n", "\r\n", $keyA),
    ], [], true);
    check('valid connect mode', [
        'mode' => 'connect', 'address' => 'ids.example.net:4789',
    ], [], true);

    // ------------------------------------------------- pre-existing rules

    check('enabled without a token', ['token' => ''], ['general.token']);
    check('connect mode without an address', ['mode' => 'connect'], ['general.address']);
    check('certificate without a key', ['client_cert' => $certA], ['general.client_key']);
    check('key without a certificate', ['client_key' => $keyA], ['general.client_cert']);

    // ------------------------------------------------ multi-instance rules
    //
    // Issue #124. Every rule below exists because breaking it leaves a segment
    // believed monitored and not monitored -- the failure the whole change is
    // about -- rather than because it looks untidy.

    // Four interfaces, four sensors: the shape the operator wanted all along.
    check('four instances, one per interface', [], [], true, [
        inst('wan', ['listen_address' => '0.0.0.0:4789']),
        inst('dmz', ['listen_address' => '0.0.0.0:4790']),
        inst('iot', ['listen_address' => '0.0.0.0:4791']),
        inst('mgmt', ['listen_address' => '0.0.0.0:4792']),
    ]);

    check('enabled plugin with no instances at all', [], ['general.enabled', 'no capture instance'], false, []);
    check('enabled plugin with only disabled instances', [], ['general.enabled'], false, [
        inst('wan', ['enabled' => '0']),
    ]);

    check('instance enabled without authorisation', [], ['authorized', '28.18'], false, [
        inst('wan', ['authorized' => '0']),
    ]);
    check('authorisation is not inherited from a sibling', [], ['authorized', 'iot'], false, [
        inst('wan'),
        inst('iot', ['authorized' => '0', 'listen_address' => '0.0.0.0:4790']),
    ]);
    check('instance enabled without an interface', [], ['interface', 'no traffic source'], false, [
        inst('wan', ['interface' => '']),
    ]);
    check('instance enabled without a sensor id', [], ['sensor_id'], false, [
        inst('wan', ['sensor_id' => '']),
    ]);

    check('duplicate instance names', [], ['name', 'already called'], false, [
        inst('wan'),
        inst('wan', ['interface' => 'opt1', 'sensor_id' => 'other', 'listen_address' => '0.0.0.0:4790']),
    ]);
    check('duplicate sensor ids', [], ['sensor_id', 'already used'], false, [
        inst('wan'),
        inst('dmz', ['sensor_id' => 'opnsense-wan', 'listen_address' => '0.0.0.0:4790']),
    ]);
    check('duplicate interfaces', [], ['interface', 'twice'], false, [
        inst('wan'),
        inst('dmz', ['interface' => 'wan', 'listen_address' => '0.0.0.0:4790']),
    ]);
    // Four processes cannot share a port: the second to start would die with
    // "address already in use" and that segment would go unmonitored.
    check('duplicate listen addresses in listen mode', [], ['listen_address', 'already uses'], false, [
        inst('wan'),
        inst('dmz'),
    ]);
    check('missing listen address in listen mode', [], ['listen_address', 'its own listen address'], false, [
        inst('wan', ['listen_address' => '']),
    ]);
    // In connect mode every instance dials the same collector, so the listen
    // address is irrelevant and sharing one is not an error.
    check('shared listen address is fine in connect mode', [
        'mode' => 'connect', 'address' => 'ids.example.net:4789',
    ], [], true, [
        inst('wan'),
        inst('dmz'),
    ]);

    // A pre-#132 configuration could store several identifiers in one field.
    // The migration splits them; if one ever survives inside a single instance,
    // saving must refuse rather than capture the first and discard the rest.
    check('a stored multi-value interface', [], ['interface', 'more than one interface'], false, [
        inst('wan', ['interface' => 'wan,opt5,opt4,opt2']),
    ]);

    // A disabled instance is a record, not a capture: only the uniqueness rules
    // apply to it, so an unauthorised disabled row saves fine.
    check('a disabled instance may be incomplete', [], [], true, [
        inst('wan'),
        inst('spare', ['enabled' => '0', 'authorized' => '0', 'interface' => '',
            'sensor_id' => '', 'listen_address' => '']),
    ]);
    // ...but it may not collide with a live one, or enabling it later would
    // silently break the sensor it collides with.
    check('a disabled instance may not reuse a name', [], ['name'], false, [
        inst('wan'),
        inst('wan', ['enabled' => '0']),
    ]);

    check('insecure TLS with an unauthorised instance', [
        'mode' => 'connect', 'address' => 'x:1', 'verify_peer' => '0',
    ], ['general.verify_peer'], false, [
        inst('wan', ['authorized' => '0']),
    ]);

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

    // ================================================================
    // Migrations\M1_0_1 -- model 1.0.0 (one sensor) to 1.0.1 (a list)
    //
    // Losing a working sensor configuration on upgrade is not acceptable, so
    // these cases are about preservation first and correctness second.
    // ================================================================

    /** Build a pre-upgrade model and run the migration over it. */
    function migrated(array $legacy): \OPNsense\SynapseIDSSensor\Sensor
    {
        $model = newModel($legacy, []);
        (new \OPNsense\SynapseIDSSensor\Migrations\M1_0_1())->run($model);
        return $model;
    }

    function items(\OPNsense\SynapseIDSSensor\Sensor $model): array
    {
        $out = [];
        foreach ($model->instances->instance->iterateItems() as $node) {
            $out[] = $node;
        }
        return $out;
    }

    // --- the case that must not lose anything: one interface, working ------
    $m = migrated([
        'enabled' => '1', 'interface' => 'wan', 'authorized' => '1',
        'sensor_id' => 'opnsense-wan', 'location' => 'hq-rack-2',
        'listen_address' => '0.0.0.0:4789', 'filter' => 'not-arp',
        'direction' => 'inout', 'promiscuous' => '0', 'snaplen' => '9000',
        'send_mode' => 'flow',
    ]);
    $one = items($m);
    assertThat('migration: a single-interface config becomes exactly one instance', count($one) === 1,
        'got ' . count($one));
    if (count($one) === 1) {
        $i = $one[0];
        assertThat('migration: the instance is named after the interface', (string)$i->name === 'wan',
            (string)$i->name);
        assertThat('migration: the interface is preserved', (string)$i->interface === 'wan');
        assertThat('migration: it stays enabled', (string)$i->enabled === '1');
        assertThat('migration: it stays authorised', (string)$i->authorized === '1');
        assertThat('migration: the sensor id is preserved', (string)$i->sensor_id === 'opnsense-wan');
        assertThat('migration: the location is preserved', (string)$i->location === 'hq-rack-2');
        assertThat('migration: the listen address is preserved',
            (string)$i->listen_address === '0.0.0.0:4789');
        assertThat('migration: the capture settings are preserved',
            (string)$i->filter === 'not-arp' && (string)$i->direction === 'inout'
            && (string)$i->promiscuous === '0' && (string)$i->snaplen === '9000'
            && (string)$i->send_mode === 'flow');
    }
    assertThat('migration: the 1.0.0 leaves are cleared', (string)$m->general->interface === ''
        && (string)$m->general->sensor_id === '' && (string)$m->general->authorized === '');
    // And the migrated model must actually validate, or the first save after an
    // upgrade would fail on a configuration the operator never touched.
    $errors = [];
    foreach ($m->performValidation(true) as $msg) {
        $errors[] = $msg->getField() . ': ' . $msg->getMessage();
    }
    assertThat('migration: the migrated configuration validates', $errors === [], implode(' | ', $errors));

    // --- a disabled 1.0.0 sensor stays disabled ---------------------------
    $m = migrated(['enabled' => '0', 'interface' => 'opt3', 'authorized' => '0']);
    $one = items($m);
    assertThat('migration: a disabled sensor migrates disabled',
        count($one) === 1 && (string)$one[0]->enabled === '0' && (string)$one[0]->authorized === '0');

    // --- the pre-#132 multi-select: four selected, one captured -----------
    $m = migrated([
        'enabled' => '1', 'interface' => 'wan,opt5,opt4,opt2', 'authorized' => '1',
        'sensor_id' => 'fw1', 'location' => 'edge', 'listen_address' => '0.0.0.0:4789',
    ]);
    $four = items($m);
    assertThat('migration: every stored identifier becomes an instance', count($four) === 4,
        'got ' . count($four));
    if (count($four) === 4) {
        assertThat('migration: the captured interface is first, enabled and authorised',
            (string)$four[0]->interface === 'wan' && (string)$four[0]->enabled === '1'
            && (string)$four[0]->authorized === '1');
        $rest = array_slice($four, 1);
        $ok = true;
        foreach ($rest as $node) {
            // The three that were selected and silently discarded. Turning them
            // into running captures behind the operator's back would be the
            // opposite mistake: PROJECT.md 28.18 makes each segment its own
            // authorisation decision.
            if ((string)$node->enabled !== '0' || (string)$node->authorized !== '0') {
                $ok = false;
            }
        }
        assertThat('migration: the never-captured interfaces arrive disabled and unauthorised', $ok);
        $ids = array_map(function ($n) {
            return (string)$n->sensor_id;
        }, $four);
        assertThat('migration: every instance gets a distinct sensor id',
            count(array_unique($ids)) === 4, implode(',', $ids));
        $names = array_map(function ($n) {
            return (string)$n->name;
        }, $four);
        assertThat('migration: every instance gets a distinct name',
            count(array_unique($names)) === 4, implode(',', $names));
        assertThat('migration: no second instance guesses a listen port',
            (string)$four[1]->listen_address === '');
    }

    // --- a fresh install must not sprout an empty instance -----------------
    $m = migrated([]);
    assertThat('migration: a fresh install creates no instances', items($m) === []);

    // --- idempotence -------------------------------------------------------
    $model = newModel(['interface' => 'wan', 'enabled' => '1', 'authorized' => '1'], []);
    $mig = new \OPNsense\SynapseIDSSensor\Migrations\M1_0_1();
    $mig->run($model);
    $mig->run($model);
    assertThat('migration: running it twice does not duplicate the instance',
        count(items($model)) === 1, 'got ' . count(items($model)));

    // --- names that are not legal instance names --------------------------
    $m = migrated(['interface' => 'opt-5,opt.5', 'enabled' => '1', 'authorized' => '1']);
    $names = array_map(function ($n) {
        return (string)$n->name;
    }, items($m));
    assertThat('migration: identifiers are sanitised into legal instance names',
        count($names) === 2 && preg_match('/^[a-zA-Z0-9_]{1,32}$/', $names[0]) === 1
        && preg_match('/^[a-zA-Z0-9_]{1,32}$/', $names[1]) === 1
        && $names[0] !== $names[1],
        implode(',', $names));

    printf("\n%d/%d cases passed\n", $ran - $failures, $ran);
    exit($failures === 0 ? 0 : 1);
}
