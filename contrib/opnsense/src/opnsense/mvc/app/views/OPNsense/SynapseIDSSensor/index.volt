{#
 # Copyright (C) 2026 SynapseIDS contributors
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 # FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
 # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #
 # ---------------------------------------------------------------------------
 # Services -> SynapseIDS Sensor.
 #
 # The form itself is generated from
 # controllers/OPNsense/SynapseIDSSensor/forms/dialogSensor.xml, handed to this
 # template by SettingsController as `formDialogSensor`.
 #
 # Endpoints used here:
 #   GET  /api/synapseidssensor/settings/get
 #   POST /api/synapseidssensor/settings/set      (also re-renders + restarts)
 #   POST /api/synapseidssensor/service/{start,stop,restart}
 #   GET  /api/synapseidssensor/service/status
 #   GET  /api/synapseidssensor/service/log
 #}

<script>
    $( document ).ready(function() {

        /**
         * Refresh the small status pill next to the service buttons.
         * updateServiceControlUI() drives the core's own service widget; the
         * pill below is ours so the page is readable even if the core widget
         * is not rendered on this page.
         */
        function refreshSensorStatus() {
            updateServiceControlUI('synapseidssensor');
            ajaxGet('/api/synapseidssensor/service/status', {}, function (data, status) {
                var state = (data && data['status']) ? data['status'] : 'unknown';
                var cls = 'label-default';
                if (state === 'running') {
                    cls = 'label-success';
                } else if (state === 'stopped') {
                    cls = 'label-danger';
                } else if (state === 'disabled') {
                    cls = 'label-default';
                } else {
                    cls = 'label-warning';
                }
                $('#sensor_status_pill')
                    .removeClass('label-success label-danger label-warning label-default')
                    .addClass(cls)
                    .text(state);
            });
        }

        /**
         * Fetch the tail of /var/log/synapseids/sensor.log through configd.
         * The API redacts the configured token before returning the text.
         */
        function refreshSensorLog() {
            $('#sensor_log').text('{{ lang._('Loading...') }}');
            ajaxGet('/api/synapseidssensor/service/log', {}, function (data, status) {
                var text = (data && data['log']) ? data['log'] : '';
                $('#sensor_log').text(text === '' ? '{{ lang._('(the sensor log is empty)') }}' : text);
            });
        }

        // ------------------------------------------------------------------
        // initial population
        // ------------------------------------------------------------------
        var data_get_map = {'frm_sensor_settings': "/api/synapseidssensor/settings/get"};
        mapDataToFormUI(data_get_map).done(function (data) {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            refreshSensorStatus();
        });

        // ------------------------------------------------------------------
        // save: settings/set writes config.xml, re-renders sensor.conf /
        // sensor.token, fixes their permissions and restarts (or stops) the
        // sensor.  No separate service/reconfigure call is needed.
        // ------------------------------------------------------------------
        // TODO(verify): saveFormToEndpoint(url, formid, callback_ok,
        // disable_dialog, callback_fail) is the OPNsense 20.x+ signature.
        // Confirm against /usr/local/opnsense/www/js/opnsense_ui.js on the
        // target release - older cores took the arguments in a different order.
        $("#saveAct").click(function () {
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
            saveFormToEndpoint("/api/synapseidssensor/settings/set", 'frm_sensor_settings', function () {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                refreshSensorStatus();
                refreshSensorLog();
            }, true, function () {
                // validation failed: base_form has already highlighted the fields
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
            });
        });

        // ------------------------------------------------------------------
        // manual service control
        // ------------------------------------------------------------------
        $(".sensor_service_act").click(function () {
            var action = $(this).data('action');   // start | stop | restart
            var $btn = $(this);
            $btn.find('i.act_progress').addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/synapseidssensor/service/" + action, {}, function (data, status) {
                $btn.find('i.act_progress').removeClass("fa fa-spinner fa-pulse");
                refreshSensorStatus();
                refreshSensorLog();
            });
        });

        $("#refreshLogAct").click(function () {
            refreshSensorLog();
        });

        refreshSensorLog();
    });
</script>

<div class="alert alert-warning" role="alert">
    <strong>{{ lang._('Monitor only what you are authorised to monitor.') }}</strong>
    {{ lang._('
        This sensor copies every frame it sees on the selected interface to a remote SynapseIDS daemon.
        Enabling it on a network you do not own, or do not have written permission to monitor, is unlawful in
        most jurisdictions. The "I am authorised to monitor this traffic" checkbox at the bottom of the form is
        mandatory: synapse-sensor refuses to capture live traffic without it (PROJECT.md 28.18).
        SynapseIDS is defensive only - it observes and classifies, it never modifies or blocks traffic.
    ') }}
</div>

<div class="alert alert-info" role="alert">
    {{ lang._('
        The bearer token is stored in the OPNsense configuration and is written to
        /usr/local/etc/synapseids/sensor.token (mode 0400, owned by _synapseids). It is handed to the sensor
        with --token-file, so it never appears in the process list, in a shell history, or in the sensor log.
        The generated /usr/local/etc/synapseids/sensor.conf contains flags only and never the token.
    ') }}
</div>

<div class="alert alert-info" role="alert">
    {{ lang._('
        TLS material entered below is kept in the OPNsense configuration, but this version of the plugin does
        not yet write it to disk. Install the PEM files manually as
        /usr/local/etc/synapseids/peer-ca.pem, sensor-cert.pem and sensor-key.pem. If a configured flag points
        at a file that is missing, the service refuses to start and names the path rather than falling back to
        a weaker transport.
    ') }}
</div>

<div class="content-box" style="padding-bottom: 1.5em;">

    {{ partial("layout_partials/base_form", ['fields': formDialogSensor, 'id': 'frm_sensor_settings']) }}

    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
        </button>
        <span class="pull-right">
            <b>{{ lang._('Service') }}:</b>
            <span id="sensor_status_pill" class="label label-default">{{ lang._('unknown') }}</span>
            {# The core service widget renders itself into this container. #}
            {# TODO(verify): on some OPNsense releases the base layout already   #}
            {# provides #service_status_container in the page header, in which  #}
            {# case updateServiceControlUI() fills that one and this element is #}
            {# simply left empty - harmless, but it can be removed.             #}
            <span id="service_status_container"></span>
            <button class="btn btn-default sensor_service_act" data-action="start" type="button">
                <i class="fa fa-play fa-fw"></i> {{ lang._('Start') }} <i class="act_progress"></i>
            </button>
            <button class="btn btn-default sensor_service_act" data-action="stop" type="button">
                <i class="fa fa-stop fa-fw"></i> {{ lang._('Stop') }} <i class="act_progress"></i>
            </button>
            <button class="btn btn-default sensor_service_act" data-action="restart" type="button">
                <i class="fa fa-refresh fa-fw"></i> {{ lang._('Restart') }} <i class="act_progress"></i>
            </button>
        </span>
    </div>
</div>

<div class="content-box" style="margin-top: 1em; padding-bottom: 1.5em;">
    <div class="col-md-12">
        <h3>
            {{ lang._('Sensor log') }}
            <button class="btn btn-default btn-xs" id="refreshLogAct" type="button">
                <i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh') }}
            </button>
        </h3>
        <p class="text-muted">
            {{ lang._('Last 200 lines of /var/log/synapseids/sensor.log, read through configd.') }}
        </p>
        <pre id="sensor_log" style="max-height: 24em; overflow: auto;"></pre>
    </div>
</div>
