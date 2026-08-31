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

namespace OPNsense\SynapseIDSSensor\Migrations;

use OPNsense\Base\BaseModelMigration;

/**
 * Model 1.0.0 -> 1.0.1: one sensor becomes a list of sensors (issue #124).
 *
 * 1.0.0 stored a single capture configuration directly under <general>.  1.0.1
 * keeps the transport and the secrets there and moves everything that describes
 * a capture into the repeating <instances><instance> node, one per interface.
 *
 * An upgrade must not cost an operator a working sensor, so this runs before
 * anything reads the new shape and is deliberately conservative:
 *
 *   - it does nothing at all unless <general><interface> holds something and the
 *     instance list is still empty, so it is idempotent and a no-op on a fresh
 *     install;
 *   - the FIRST identifier becomes an instance carrying every 1.0.0 value
 *     verbatim, including `enabled` and `authorized`.  A firewall that was
 *     capturing WAN before the upgrade is still capturing WAN after it;
 *   - any FURTHER identifiers - which only a pre-#132 multi-select could have
 *     stored, and which the 1.0.0 template silently discarded - also become
 *     instances, but DISABLED and NOT AUTHORISED.
 *
 * That last point is the whole reason this migration is interesting.  On a live
 * gateway an operator selected WAN, IoT, DMZ and MGMT and got a single VLAN
 * captured; three segments were believed monitored and were not.  Turning those
 * three into running sensors behind their back would be the opposite mistake:
 * §28.18 makes capturing a segment an explicit authorisation decision, and an
 * assertion made about the WAN uplink is not an assertion about a tenant VLAN.
 * So they arrive as visible, named, switched-off rows that say exactly what they
 * are, and the operator ticks each one deliberately.
 *
 * @package OPNsense\SynapseIDSSensor\Migrations
 */
class M1_0_1 extends BaseModelMigration
{
    /**
     * Read a legacy <general> leaf as a trimmed string.
     *
     * @param mixed  $general the model's general node
     * @param string $name    leaf name
     * @return string
     */
    private function legacy($general, string $name): string
    {
        if (!isset($general->$name)) {
            return '';
        }
        $node = $general->$name;
        return $node === null ? '' : trim((string)$node);
    }

    /**
     * Turn an OPNsense interface identifier into an instance name that is legal
     * as a filename, an rc.d profile and a shell word: letters, digits and
     * underscore only, never empty, never a duplicate.
     *
     * @param string   $identifier interface identifier such as "wan" or "opt5"
     * @param string[] $taken      names already used, by reference
     * @return string
     */
    private function instanceName(string $identifier, array &$taken): string
    {
        $name = preg_replace('/[^a-zA-Z0-9_]/', '_', $identifier);
        $name = substr((string)$name, 0, 32);
        if ($name === '' || $name === '_') {
            $name = 'sensor';
        }
        $base = $name;
        $n = 2;
        while (in_array($name, $taken, true)) {
            // Keep the suffix inside the 32 character Mask.
            $suffix = (string)$n;
            $name = substr($base, 0, 32 - strlen($suffix) - 1) . '_' . $suffix;
            $n++;
        }
        $taken[] = $name;
        return $name;
    }

    /**
     * Perform the migration.
     *
     * @param \OPNsense\Base\BaseModel $model the Sensor model, bound to config.xml
     * @return void
     */
    public function run($model)
    {
        // Defaults for anything the 1.0.1 model requires but 1.0.0 never stored.
        parent::run($model);

        $general = $model->general;
        $stored = $this->legacy($general, 'interface');
        if ($stored === '') {
            // Fresh install, or a 1.0.0 configuration that never picked an
            // interface. There is nothing to preserve, and inventing an empty
            // instance would only produce a validation error on the first save.
            return;
        }

        // Already migrated (or hand-built): never touch an existing list.
        foreach ($model->instances->instance->iterateItems() as $ignored) {
            return;
        }

        // "wan" -> ["wan"]; the pre-#132 "wan,opt5,opt4,opt2" -> all four.
        $identifiers = [];
        foreach (explode(',', $stored) as $part) {
            $part = trim($part);
            if ($part !== '' && !in_array($part, $identifiers, true)) {
                $identifiers[] = $part;
            }
        }

        $legacySensorId = $this->legacy($general, 'sensor_id');
        $legacyLocation = $this->legacy($general, 'location');
        $taken = [];

        foreach ($identifiers as $index => $identifier) {
            $node = $model->instances->instance->Add();
            $name = $this->instanceName($identifier, $taken);

            $node->name = $name;
            $node->interface = $identifier;
            $node->location = $legacyLocation;

            // Everything below is copied verbatim only for the interface that
            // was ACTUALLY being captured before the upgrade - the first one.
            if ($index === 0) {
                $node->enabled = $this->legacy($general, 'enabled') === '1' ? '1' : '0';
                $node->authorized = $this->legacy($general, 'authorized') === '1' ? '1' : '0';
                $node->sensor_id = $legacySensorId !== '' ? $legacySensorId : $name;
                $this->copyIfSet($node, 'listen_address', $this->legacy($general, 'listen_address'));
                $this->copyIfSet($node, 'filter', $this->legacy($general, 'filter'));
                $this->copyIfSet($node, 'direction', $this->legacy($general, 'direction'));
                $this->copyIfSet($node, 'promiscuous', $this->legacy($general, 'promiscuous'));
                $this->copyIfSet($node, 'snaplen', $this->legacy($general, 'snaplen'));
                $this->copyIfSet($node, 'send_mode', $this->legacy($general, 'send_mode'));
                $node->description = 'Migrated from the single-sensor configuration (model 1.0.0).';
                continue;
            }

            // The interfaces the 1.0.0 template threw away. They are recorded so
            // the operator can see what was selected, and switched off so that
            // an upgrade never starts capturing a segment nobody asserted
            // authorisation for (PROJECT.md §28.18).
            $node->enabled = '0';
            $node->authorized = '0';
            $node->sensor_id = ($legacySensorId !== '' ? $legacySensorId : 'sensor') . '-' . $name;
            // No listen address: two processes cannot share a port, and there is
            // no safe way to guess a second one. Enabling the instance in listen
            // mode without one is refused at save time, with a message saying so.
            $node->listen_address = '';
            $this->copyIfSet($node, 'filter', $this->legacy($general, 'filter'));
            $this->copyIfSet($node, 'direction', $this->legacy($general, 'direction'));
            $this->copyIfSet($node, 'promiscuous', $this->legacy($general, 'promiscuous'));
            $this->copyIfSet($node, 'snaplen', $this->legacy($general, 'snaplen'));
            $this->copyIfSet($node, 'send_mode', $this->legacy($general, 'send_mode'));
            // No colon and no apostrophe here - the description Mask allows
            // letters, digits, space and . _ / , ( ) - and nothing else.
            $node->description =
                'Selected in the old multi-interface field but never captured. ' .
                'Disabled until authorisation for this segment is confirmed.';
        }

        // Blank the 1.0.0 leaves. They stay declared in Sensor.xml only so this
        // migration can read them; leaving the values behind would mean a second
        // stale copy of the configuration on every firewall.
        foreach (
            [
                'interface', 'filter', 'direction', 'promiscuous', 'snaplen',
                'send_mode', 'listen_address', 'sensor_id', 'location', 'authorized',
            ] as $leaf
        ) {
            if (isset($general->$leaf)) {
                $general->$leaf = '';
            }
        }
    }

    /**
     * Copy a legacy value onto the instance only when it holds something, so an
     * unset 1.0.0 leaf keeps the 1.0.1 default instead of blanking a required
     * field.
     *
     * @param mixed  $node  instance node
     * @param string $field field name on the instance
     * @param string $value legacy value
     * @return void
     */
    private function copyIfSet($node, string $field, string $value): void
    {
        if ($value !== '') {
            $node->$field = $value;
        }
    }
}
