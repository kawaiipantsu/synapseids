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

use OPNsense\Base\IndexController;

/**
 * Class SettingsController
 *
 * Renders Services -> SynapseIDS Sensor.  This controller carries no business
 * logic at all: it hands the form definition (controllers/.../forms/dialogSensor.xml)
 * to the Volt template, which then talks exclusively to
 * /api/synapseidssensor/settings/* and /api/synapseidssensor/service/*.
 *
 * Reachable as /ui/synapseidssensor/settings.
 *
 * @package OPNsense\SynapseIDSSensor
 */
class SettingsController extends IndexController
{
    /**
     * Default page.
     *
     * @return void
     */
    public function indexAction()
    {
        $this->view->title = gettext('SynapseIDS Sensor');

        // Form definition lives in forms/dialogSensor.xml next to this file.
        // getForm() resolves it relative to the controller directory.
        $this->view->formDialogSensor = $this->getForm('dialogSensor');

        $this->view->pick('OPNsense/SynapseIDSSensor/index');
    }
}
