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
     * TODO(verify): getModelNodes()/setModelNodes() are provided by
     * ApiMutableModelControllerBase on OPNsense 19.7 and later.  If this plugin
     * ever has to build against an older core, replace them with
     * `$this->getModel()->getNodes()` and an explicit `setNodes()` + `save()`.
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

        $result = $this->setModelNodes();

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

        // Renders /usr/local/etc/synapseids/sensor.conf and sensor.token.
        $steps['template'] = trim($backend->configdRun('template reload OPNsense/SynapseIDSSensor'));

        // Templates land as root:wheel 0644; the token must not stay that way.
        $steps['fixperms'] = trim($backend->configdRun('synapseidssensor fixperms'));

        $enabled = (string)$this->getModel()->general->enabled === '1';
        $steps['service'] = trim($backend->configdRun(
            $enabled ? 'synapseidssensor restart' : 'synapseidssensor stop'
        ));

        return $steps;
    }
}
