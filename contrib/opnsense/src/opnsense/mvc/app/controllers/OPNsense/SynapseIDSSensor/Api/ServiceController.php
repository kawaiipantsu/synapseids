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
     * Instance name accepted on a configd command line.
     *
     * configd already single-quotes every parameter, so this is not about shell
     * quoting; it is about a name like "../../etc" turning the log endpoint into
     * an arbitrary-file reader. The pattern is the model's own Mask, so anything
     * that could have been saved passes and anything else becomes "" -- which
     * every action reads as "all instances".
     *
     * @param mixed $value raw parameter from the request
     * @return string the validated name, or '' for all instances
     */
    private function instanceParam($value): string
    {
        $name = trim((string)$value);
        return preg_match('/^[a-zA-Z0-9_]{1,32}$/', $name) === 1 ? $name : '';
    }

    /**
     * Build the configd command, appending the instance only when there is one.
     *
     * @param string $action configd action name
     * @param mixed  $inst   requested instance, unvalidated
     * @return string
     */
    private function configdCommand(string $action, $inst): string
    {
        $name = $this->instanceParam($inst);
        return $name === '' ? 'synapseidssensor ' . $action : 'synapseidssensor ' . $action . ' ' . $name;
    }

    /**
     * Per-instance service control (issue #124).
     *
     * The base class's start/stop/restart still act on the whole plugin, which
     * is what the page's main buttons want. These four are the per-instance
     * equivalents, and they exist because taking one segment out of service
     * should not interrupt the capture of the other three.
     *
     * @param string|null $instance instance name
     * @return array {"status": "ok", "response": "..."}
     */
    public function instanceStartAction($instance = null)
    {
        return $this->instanceAction('start', $instance);
    }

    /**
     * @param string|null $instance instance name
     * @return array
     */
    public function instanceStopAction($instance = null)
    {
        return $this->instanceAction('stop', $instance);
    }

    /**
     * @param string|null $instance instance name
     * @return array
     */
    public function instanceRestartAction($instance = null)
    {
        return $this->instanceAction('restart', $instance);
    }

    /**
     * @param string|null $instance instance name
     * @return array
     */
    public function instanceStatusAction($instance = null)
    {
        return $this->instanceAction('status', $instance);
    }

    /**
     * @param string      $action   configd action
     * @param string|null $instance instance name
     * @return array
     */
    private function instanceAction(string $action, $instance): array
    {
        $name = $this->instanceParam($instance);
        if ($name === '') {
            return ['status' => 'failed', 'response' => gettext('A sensor instance name is required.')];
        }
        $this->sessionClose();
        $out = (string)(new Backend())->configdRun('synapseidssensor ' . $action . ' ' . $name);
        return ['status' => 'ok', 'instance' => $name, 'response' => trim($out)];
    }

    /**
     * Per-instance running state, for the settings page.
     *
     * The core service widget reduces the whole plugin to one word, and with
     * four sensor processes that word is wrong more often than it is right: one
     * stopped instance reports the entire service as stopped, and -- far worse
     * for this plugin in particular -- three stopped instances alongside one
     * running one could read as healthy on a widget that latched onto the first
     * "is running" line. So the page shows the breakdown, and it comes from
     * here: one entry per configured instance, with the rc.d script's own
     * answer for each.
     *
     * @return array {"status":"ok","instances":[{"name":..,"enabled":..,"state":..}, ...]}
     */
    public function instancesAction()
    {
        $this->sessionClose();

        $model = new \OPNsense\SynapseIDSSensor\Sensor();
        $backend = new Backend();
        $out = [];

        foreach ($model->instances->instance->iterateItems() as $node) {
            $name = $this->instanceParam((string)$node->name);
            if ($name === '') {
                continue;
            }
            $text = (string)$backend->configdRun('synapseidssensor status ' . $name);
            $state = 'unknown';
            if (stripos($text, 'is running') !== false) {
                $state = 'running';
            } elseif (stripos($text, 'not running') !== false) {
                $state = 'stopped';
            }
            if ((string)$node->enabled !== '1') {
                // A disabled instance that is not running is the expected state,
                // not a fault; saying "stopped" next to three "running" rows
                // reads as a problem and sends people looking for one.
                $state = $state === 'running' ? 'running' : 'disabled';
            }
            $out[] = [
                'name' => $name,
                'enabled' => (string)$node->enabled === '1',
                'authorized' => (string)$node->authorized === '1',
                'interface' => (string)$node->interface,
                'sensor_id' => (string)$node->sensor_id,
                'state' => $state,
            ];
        }

        return ['status' => 'ok', 'instances' => $out];
    }

    /**
     * Tail of /var/log/synapseids/<instance>/sensor.log, or of every instance's
     * log when no instance is named.
     *
     * The bearer token cannot appear here: synapse-sensor reads it from
     * --token-file and never logs its value, and the rc.d wrapper never echoes
     * it either.  As a belt-and-braces measure the configured token is redacted
     * from the returned text before it leaves the API, so a future logging
     * regression on the Go side cannot turn this endpoint into a token oracle.
     *
     * @param string|null $instance instance name, or null for every instance
     * @return array {"status": "ok", "log": "..."}
     */
    public function logAction($instance = null)
    {
        if (!$this->request->isGet() && !$this->request->isPost()) {
            return ['status' => 'failed', 'log' => ''];
        }

        $this->sessionClose();

        $backend = new Backend();
        $log = (string)$backend->configdRun($this->configdCommand('log', $instance));

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
     * With no instance name it runs for every configured instance and prints the
     * instance in its own column on every line, so `grep FAIL` on the output
     * still says WHICH sensor is broken; with one it checks only that instance.
     *
     * The command is read-only and prints no secrets -- only paths, modes and
     * certificate subjects.  The configured token is nevertheless redacted from
     * the response, exactly as in logAction(), so that a future change to the
     * selftest output can never turn this endpoint into a token oracle.
     *
     * @param string|null $instance instance name, or null for every instance
     * @return array {"status": "ok", "output": "..."}
     */
    public function selftestAction($instance = null)
    {
        if (!$this->request->isGet() && !$this->request->isPost()) {
            return ['status' => 'failed', 'output' => ''];
        }

        $this->sessionClose();

        $backend = new Backend();
        $output = (string)$backend->configdRun($this->configdCommand('selftest', $instance));

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
