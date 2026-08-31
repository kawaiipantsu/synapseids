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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 *
 * Service control for synapse-sensor.  ApiMutableServiceControllerBase already
 * supplies:
 *
 *   POST /api/synapseidssensor/service/start
 *   POST /api/synapseidssensor/service/stop
 *   POST /api/synapseidssensor/service/restart
 *   POST /api/synapseidssensor/service/reconfigure   (template reload + start/stop)
 *   GET  /api/synapseidssensor/service/status
 *
 * all of which go through configd; this controller never shells out itself.
 * The only addition is logAction(), which returns the tail of the sensor log so
 * an operator can see why a start failed without leaving the web UI.
 *
 * @package OPNsense\SynapseIDSSensor\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    /**
     * @var string model consulted for the enabled flag
     */
    protected static $internalServiceClass = '\OPNsense\SynapseIDSSensor\Sensor';

    /**
     * @var string configd template set re-rendered by reconfigure
     */
    protected static $internalServiceTemplate = 'OPNsense/SynapseIDSSensor';

    /**
     * @var string model path that decides whether the service should run
     */
    protected static $internalServiceEnabled = 'general.enabled';

    /**
     * @var string configd action prefix, i.e. actions_synapseidssensor.conf
     */
    protected static $internalServiceName = 'synapseidssensor';

    /**
     * Tail of /var/log/synapseids/sensor.log.
     *
     * The bearer token cannot appear here: synapse-sensor reads it from
     * --token-file and never logs its value, and the rc.d wrapper never echoes
     * it either.  As a belt-and-braces measure the configured token is redacted
     * from the returned text before it leaves the API, so a future logging
     * regression on the Go side cannot turn this endpoint into a token oracle.
     *
     * @return array {"status": "ok", "log": "..."}
     */
    public function logAction()
    {
        if (!$this->request->isGet() && !$this->request->isPost()) {
            return ['status' => 'failed', 'log' => ''];
        }

        $this->sessionClose();

        $backend = new Backend();
        $log = (string)$backend->configdRun('synapseidssensor log');

        // TODO(verify): ApiMutableServiceControllerBase exposes a protected
        // getModel() that instantiates $internalServiceClass (it is what
        // isEnabled() uses).  Confirm the helper name on the target core; if it
        // is absent, replace this with
        // `(new \OPNsense\SynapseIDSSensor\Sensor())->general->token`.
        $token = trim((string)$this->getModel()->general->token);
        if ($token !== '') {
            $log = str_replace($token, '***redacted***', $log);
        }

        return ['status' => 'ok', 'log' => trim($log)];
    }
}
