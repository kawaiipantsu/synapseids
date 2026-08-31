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

namespace OPNsense\SynapseIDSSensor\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

/**
 * Class SettingsController
 *
 * REST surface for the sensor configuration:
 *
 *   GET  /api/synapseidssensor/settings/get   -> {"sensor": {...}}
 *   POST /api/synapseidssensor/settings/set   -> save + re-render + (re)start
 *
 * setAction() deliberately performs the whole reconfigure cycle so a single
 * round trip from the UI leaves the box consistent:
 *
 *   1. write config.xml (via the model, which runs Sensor::performValidation)
 *   2. `template reload OPNsense/SynapseIDSSensor`  - re-renders sensor.conf
 *      and sensor.token
 *   3. `synapseidssensor fixperms`                  - the freshly rendered
 *      sensor.token is owned by root and world readable until this runs
 *   4. `synapseidssensor restart` (or `stop` when disabled)
 *
 * Because of step 2 the index.volt page does NOT additionally call
 * service/reconfigure; doing both would restart the capture twice.
 *
 * Nothing here ever echoes the bearer token: the response is the model's own
 * node tree (which the authenticated, ACL-guarded UI needs in order to render
 * the form) and the configd status strings, which contain no secrets.
 *
 * @package OPNsense\SynapseIDSSensor\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    /**
     * @var string POST payload key and response key
     */
    protected static $internalModelName = 'sensor';

    /**
     * @var string backing model
     */
    protected static $internalModelClass = '\OPNsense\SynapseIDSSensor\Sensor';

    /**
     * Return the full settings tree.
     *
     * getModelNodes()/setModelNodes() are provided by
     * ApiMutableModelControllerBase on OPNsense 19.7 and later, and this plugin
     * is packaged only for FreeBSD 14 cores -- OPNsense 24.x/25.x -- so they are
     * present.  A pre-19.7 core is explicitly out of scope; there the
     * replacement is `$this->getModel()->getNodes()` plus an explicit
     * `setNodes()` + `save()`.
     *
     * @return array
     */
    public function getAction()
    {
        return $this->getModelNodes();
    }

    /**
     * Persist the settings and apply them.
     *
     * @return array {"result": "saved"} or {"result": "failed", "validations": {...}}
     */
    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => gettext('POST required.')];
        }

        // ApiMutableModelControllerBase provides getModelNodes() for the read
        // side but there is NO symmetric setModelNodes(). Assuming there was
        // cost an entire hardware bring-up: every POST died with
        //   Error: Call to undefined method ...::setModelNodes()
        // which the MVC layer turns into HTTP 500 and the GUI reports as
        // "Unexpected error, check log for details". GET worked throughout,
        // because getModelNodes() is real -- so the settings page looked
        // healthy and Save silently never wrote config.xml.
        //
        // Delegate to the base class's own setAction() rather than
        // reimplementing it. get_class_methods() on a live OPNsense 25.1 shows
        // setAction() among the PUBLIC methods of
        // ApiMutableModelControllerBase, so parent::setAction() is guaranteed to
        // exist -- whereas open-coding setNodes()/save() here would depend on
        // protected members whose names are exactly what went wrong above.
        // It returns the same {"result":"saved"} /
        // {"result":"failed","validations":{...}} shape this method promises.
        $result = parent::setAction();

        if (isset($result['result']) && $result['result'] === 'saved') {
            $result['reconfigure'] = $this->applyConfiguration();
        }

        return $result;
    }

    /**
     * Re-render the configd templates and bring the service in line with the
     * saved "enabled" flag.
     *
     * @return array per-step configd output, for troubleshooting in the UI
     */
    private function applyConfiguration(): array
    {
        // configd calls block; release the session lock so the UI stays usable.
        $this->sessionClose();

        $backend = new Backend();
        $steps = [];

        // Renders all five targets under /usr/local/etc/synapseids/:
        // sensor.conf, sensor.token, sensor-ca.pem, sensor-cert.pem and
        // sensor-key.pem (issue #104).
        $steps['template'] = trim($backend->configdRun('template reload OPNsense/SynapseIDSSensor'));

        // Templates land as root:wheel 0644 under configd's umask. The two
        // secrets -- the bearer token and the TLS private key -- must not stay
        // that way for even a moment longer than necessary, so this runs
        // immediately, before the service is touched.
        $steps['fixperms'] = trim($backend->configdRun('synapseidssensor fixperms'));

        $enabled = (string)$this->getModel()->general->enabled === '1';
        $steps['service'] = trim($backend->configdRun(
            $enabled ? 'synapseidssensor restart' : 'synapseidssensor stop'
        ));

        // A sensor that refuses to start is an EXPECTED state on a firewall that
        // has not been granted /dev/bpf* access yet, or whose interface has not
        // resolved. By this point the configuration IS saved -- the template and
        // fixperms steps above have already run -- so the failure is about the
        // service, not the settings.
        //
        // The problem is that configd's type:script actions return only
        // "Error (1)". The rc script prints a precise reason (which device, which
        // lookup, the exact devfs incantation) and all of it is discarded, so the
        // operator sees a bare error and has to SSH in to find out why. That is
        // what made a simple missing devfs rule take several rounds to identify
        // on a real gateway.
        //
        // The selftest action is type:script_output, so its text does come back.
        // Attach it on failure: one line per check, naming the cause.
        if (stripos($steps['service'], 'error') !== false) {
            $steps['selftest'] = trim($backend->configdRun('synapseidssensor selftest'));
        }

        return $steps;
    }
}
