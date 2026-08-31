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
 *
 * Three additions:
 *
 *   - logAction()      the tail of the sensor log, so an operator can see why a
 *                      start failed without leaving the web UI;
 *   - selftestAction()  `synapse-sensor doctor` through configd -- the on-box
 *                      diagnostic for a sensor that will not start or that
 *                      starts but captures nothing (issue #102);
 *   - reconfigureAction() overridden only to re-clamp file permissions after the
 *                      parent re-renders the templates (issue #104).
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

        // The model is instantiated directly rather than through a base-class
        // helper.  ApiMutableServiceControllerBase does expose a getModel(), but
        // depending on it here bought nothing and could not be confirmed from a
        // Linux build host -- so the dependency is simply removed.  One `new` on
        // a rarely-hit endpoint is cheaper than an unverifiable assumption.
        $token = trim((string)(new \OPNsense\SynapseIDSSensor\Sensor())->general->token);
        if ($token !== '') {
            $log = str_replace($token, '***redacted***', $log);
        }

        return ['status' => 'ok', 'log' => trim($log)];
    }

    /**
     * Run the on-box selftest and return its output verbatim.
     *
     * This is `synapse-sensor doctor` by way of the rc.d script's `selftest`
     * verb: it checks the binary, the service account, /dev/bpf* access, that
     * the configured interface resolved to a device that EXISTS, that the
     * rendered configuration parses, that the token is 0400, that the TLS
     * material parses and the key pair matches, and that the collector answers a
     * TCP connect.  One `[ OK ]` / `[WARN]` / `[FAIL]` / `[SKIP]` line each.
     *
     * The command is read-only and prints no secrets -- only paths, modes and
     * certificate subjects.  The configured token is nevertheless redacted from
     * the response, exactly as in logAction(), so that a future change to the
     * selftest output can never turn this endpoint into a token oracle.
     *
     * @return array {"status": "ok", "output": "..."}
     */
    public function selftestAction()
    {
        if (!$this->request->isGet() && !$this->request->isPost()) {
            return ['status' => 'failed', 'output' => ''];
        }

        $this->sessionClose();

        $backend = new Backend();
        $output = (string)$backend->configdRun('synapseidssensor selftest');

        $token = trim((string)(new \OPNsense\SynapseIDSSensor\Sensor())->general->token);
        if ($token !== '') {
            $output = str_replace($token, '***redacted***', $output);
        }

        return ['status' => 'ok', 'output' => trim($output)];
    }

    /**
     * Re-render the templates, then re-clamp the permissions on what was
     * rendered.
     *
     * The parent issues `template reload` itself, and configd renders as root
     * under its own umask -- which since issue #104 means a freshly written TLS
     * private key, not just the bearer token.  The rc.d start_precmd tightens
     * both before every start, so a reconfigure that also starts the service is
     * already covered; this closes the case where the service stays stopped and
     * a secret would otherwise sit mode 0644 indefinitely.
     *
     * @return array the parent's result, unchanged
     */
    public function reconfigureAction()
    {
        $result = parent::reconfigureAction();
        (new Backend())->configdRun('synapseidssensor fixperms');
        return $result;
    }
}
