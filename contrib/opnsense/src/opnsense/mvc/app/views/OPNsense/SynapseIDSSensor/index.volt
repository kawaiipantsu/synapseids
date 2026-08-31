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
 # Two forms, generated from
 # controllers/OPNsense/SynapseIDSSensor/forms/ and handed to this template by
 # SettingsController as `formDialogSensor` (the shared transport settings) and
 # `formDialogInstance` (one capture instance, edited from the grid).
 #
 # Endpoints used here:
 #   GET  /api/synapseidssensor/settings/get
 #   POST /api/synapseidssensor/settings/set          (also re-renders + restarts)
 #   *    /api/synapseidssensor/settings/{search,get,add,set,del,toggle}Instance
 #   POST /api/synapseidssensor/service/{start,stop,restart}
 #   GET  /api/synapseidssensor/service/status
 #   GET  /api/synapseidssensor/service/instances     (per-instance state)
 #   GET  /api/synapseidssensor/service/log[/<name>]
 #   GET  /api/synapseidssensor/service/selftest[/<name>]
 #}

<script>
    $( document ).ready(function() {

        /**
         * The instance grid. This is the stock UIBootgrid wiring every core page
         * with a repeating item uses; the dialog it opens is
         * forms/dialogInstance.xml.
         *
         * Note what the toggle does NOT do: it never sets the authorisation
         * checkbox. Enabling a capture and asserting that you may capture that
         * segment are two decisions (PROJECT.md 28.18), so toggling on a row
         * that was never authorised fails validation and sends the operator into
         * the dialog to make the assertion explicitly.
         */
        $("#grid-instances").UIBootgrid({
            search: '/api/synapseidssensor/settings/searchInstance/',
            get:    '/api/synapseidssensor/settings/getInstance/',
            set:    '/api/synapseidssensor/settings/setInstance/',
            add:    '/api/synapseidssensor/settings/addInstance/',
            del:    '/api/synapseidssensor/settings/delInstance/',
            toggle: '/api/synapseidssensor/settings/toggleInstance/'
        });

        /**
         * Refresh the small status pill next to the service buttons, and the
         * per-instance breakdown under the grid.
         *
         * The core widget reduces four processes to one word. With one sensor
         * stopped and three running it says "stopped", which is pessimistic but
         * safe; what is NOT safe is an operator reading one word and believing
         * every segment is covered. So the breakdown below it is the thing to
         * look at, and it names every instance.
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
            refreshInstanceStates();
        }

        /** One badge per configured instance, plus the instance selectors. */
        function refreshInstanceStates() {
            ajaxGet('/api/synapseidssensor/service/instances', {}, function (data, status) {
                var rows = (data && data['instances']) ? data['instances'] : [];
                var $box = $('#sensor_instance_states').empty();
                var $sel = $('#sensor_instance_select');
                var current = $sel.val();
                $sel.empty().append($('<option/>').val('').text('{{ lang._('All instances') }}'));

                if (rows.length === 0) {
                    $box.append($('<span class="text-muted"/>').text(
                        '{{ lang._('No sensor instances are configured. Add one per interface above.') }}'));
                    return;
                }
                $.each(rows, function (i, row) {
                    var cls = 'label-default';
                    if (row['state'] === 'running') {
                        cls = 'label-success';
                    } else if (row['state'] === 'stopped') {
                        cls = 'label-danger';
                    } else if (row['state'] === 'unknown') {
                        cls = 'label-warning';
                    }
                    var text = row['name'] + ': ' + row['state'];
                    if (row['enabled'] && !row['authorized']) {
                        text = text + ' (not authorised)';
                        cls = 'label-danger';
                    }
                    $box.append($('<span/>').addClass('label ' + cls)
                        .css('margin-right', '0.5em').text(text));
                    $sel.append($('<option/>').val(row['name']).text(row['name']));
                });
                if (current) {
                    $sel.val(current);
                }
            });
        }

        /** Which instance the log and selftest panes are showing. '' = all. */
        function selectedInstance() {
            var v = $('#sensor_instance_select').val();
            return v ? '/' + encodeURIComponent(v) : '';
        }

        /**
         * Fetch the tail of /var/log/synapseids/<instance>/sensor.log through
         * configd. The API redacts the configured token before returning it.
         */
        function refreshSensorLog() {
            $('#sensor_log').text('{{ lang._('Loading...') }}');
            ajaxGet('/api/synapseidssensor/service/log' + selectedInstance(), {}, function (data, status) {
                var text = (data && data['log']) ? data['log'] : '';
                $('#sensor_log').text(text === '' ? '{{ lang._('(the sensor log is empty)') }}' : text);
            });
        }

        /**
         * Run the on-box selftest (`synapse-sensor doctor` per instance, via the
         * rc.d selftest verb and configd) and show its output verbatim.
         *
         * This is the single most useful button on the page when a sensor will
         * not start, or starts but captures nothing: it reports the binary, the
         * service account, /dev/bpf* access, whether each configured interface
         * resolved to a device that actually EXISTS, whether each rendered
         * configuration parses, the token mode, whether the TLS material parses
         * and matches, and whether the collector answers a TCP connect - one
         * line per check, with the instance name in its own column.
         */
        function runSensorSelftest() {
            $('#sensor_selftest').text('{{ lang._('Running the selftest...') }}');
            ajaxGet('/api/synapseidssensor/service/selftest' + selectedInstance(), {}, function (data, status) {
                var text = (data && data['output']) ? data['output'] : '';
                if (text === '') {
                    text = '{{ lang._('(the selftest produced no output -- is the plugin installed correctly?)') }}';
                }
                $('#sensor_selftest').text(text);
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

            // An upgrade from the single-sensor model runs Migrations/M1_0_1,
            // which turns the old <general> settings into the first instance.
            // If that never ran -- a package installed without its post-install,
            // typically -- the page would look like a fresh install and the
            // operator's working configuration would appear to have vanished.
            // It has not: it is still in config.xml, and one command recovers it.
            var legacy = (data && data['sensor'] && data['sensor']['general'])
                ? data['sensor']['general']['interface'] : '';
            if (legacy) {
                $('#sensor_migration_warning').show();
            }
        });

        // ------------------------------------------------------------------
        // save: settings/set writes config.xml, re-renders the index and every
        // instance's configuration, fixes their permissions and restarts (or
        // stops) the sensors.  No separate service/reconfigure call is needed.
        // ------------------------------------------------------------------
        // saveFormToEndpoint(url, formid, callback_ok, disable_dialog,
        // callback_fail) is the signature in
        // /usr/local/opnsense/www/js/opnsense_ui.js on every OPNsense 20.x and
        // later core, which is what this plugin is packaged for. If it were
        // wrong the Save button would visibly do nothing and the browser console
        // would say so on the first click - an immediate, loud failure during
        // installation, not a silent one.
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
        // manual service control (every instance)
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

        // ------------------------------------------------------------------
        // manual service control (one instance)
        // ------------------------------------------------------------------
        $(".sensor_instance_act").click(function () {
            var name = $('#sensor_instance_select').val();
            if (!name) {
                return;
            }
            var action = $(this).data('action');   // instanceStart | ...
            var $btn = $(this);
            $btn.find('i.act_progress').addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/synapseidssensor/service/" + action + "/" + encodeURIComponent(name), {},
                function (data, status) {
                    $btn.find('i.act_progress').removeClass("fa fa-spinner fa-pulse");
                    refreshSensorStatus();
                    refreshSensorLog();
                });
        });

        $("#refreshLogAct").click(function () {
            refreshSensorLog();
        });

        $("#sensor_instance_select").change(function () {
            refreshSensorLog();
            $('#sensor_selftest').text('{{ lang._('Press "Run selftest".') }}');
        });

        $("#selftestAct").click(function () {
            $("#selftestAct_progress").addClass("fa fa-spinner fa-pulse");
            runSensorSelftest();
            $("#selftestAct_progress").removeClass("fa fa-spinner fa-pulse");
        });

        refreshSensorLog();
    });
</script>

<div class="alert alert-warning" role="alert">
    <strong>{{ lang._('Monitor only what you are authorised to monitor.') }}</strong>
    {{ lang._('
        Each sensor instance copies every frame it sees on its interface to a remote SynapseIDS daemon.
        Enabling one on a network you do not own, or do not have written permission to monitor, is unlawful in
        most jurisdictions. The "I am authorised to monitor this interface" checkbox is mandatory on EVERY
        instance and is never inherited from another one: being allowed to monitor the WAN uplink is not
        being allowed to monitor a tenant VLAN. synapse-sensor refuses to capture live traffic without
        --authorized (PROJECT.md 28.18). SynapseIDS is defensive only - it observes and classifies, it never
        modifies or blocks traffic.
    ') }}
</div>

<div class="alert alert-danger" role="alert" id="sensor_migration_warning" style="display: none;">
    <strong>{{ lang._('This firewall still holds a single-sensor configuration that has not been migrated.') }}</strong>
    {{ lang._('
        Nothing has been lost - the old settings are still stored - but until the migration runs, the sensor
        list below is empty and no capture is configured. Run this once, from the console:
    ') }}
    <pre>/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/SynapseIDSSensor</pre>
    {{ lang._('
        then reload this page. The interface that was being captured returns as an enabled instance; any
        further interfaces that the old multi-select accepted but never actually captured return as disabled,
        unauthorised instances for you to review.
    ') }}
</div>

<div class="alert alert-info" role="alert">
    {{ lang._('
        The bearer token is stored in the OPNsense configuration and is written to
        /usr/local/etc/synapseids/sensor.token (mode 0400, owned by _synapseids). It is handed to every sensor
        with --token-file, so it never appears in the process list, in a shell history, or in a sensor log.
        The generated /usr/local/etc/synapseids/instances/&lt;name&gt;.conf files contain flags only and never
        the token.
    ') }}
</div>

<div class="alert alert-info" role="alert">
    {{ lang._('
        TLS material entered below is written to disk for you when you save: sensor-ca.pem and
        sensor-cert.pem as 0444 root:wheel, and the private key as /usr/local/etc/synapseids/sensor-key.pem,
        mode 0400 owned by _synapseids - clamped immediately after rendering, exactly like the bearer token.
        Nothing needs to be copied to the firewall by hand. If a configured flag points at a PEM that is
        missing, empty or unparseable, the service refuses to start and names the path rather than falling
        back to a weaker transport.
    ') }}
</div>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="col-md-12">
        <h3>{{ lang._('Sensor instances') }}</h3>
        <p class="text-muted">
            {{ lang._('
                One synapse-sensor process per interface. Each instance has its own sensor identity, its own
                rendered configuration, its own pidfile and its own log, so a packet routed between two
                monitored segments is reported twice by two named sensors instead of two observations
                collapsing into one flow. Adding an instance here does not start it: press Save.
            ') }}
        </p>
    </div>
    <table id="grid-instances" class="table table-condensed table-hover table-striped"
           data-editDialog="DialogInstance" data-editAlert="sensorInstanceChangeMessage">
        <thead>
            <tr>
                <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                <th data-column-id="name" data-type="string">{{ lang._('Name') }}</th>
                <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                <th data-column-id="sensor_id" data-type="string">{{ lang._('Sensor ID') }}</th>
                <th data-column-id="location" data-type="string">{{ lang._('Location') }}</th>
                <th data-column-id="send_mode" data-type="string">{{ lang._('Send') }}</th>
                <th data-column-id="authorized" data-width="8em" data-type="string">{{ lang._('Authorised') }}</th>
                <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
        <tfoot>
            <tr>
                <td></td>
                <td colspan="9">
                    <button data-action="add" type="button" class="btn btn-xs btn-default">
                        <span class="fa fa-plus fa-fw"></span>
                    </button>
                    <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default">
                        <span class="fa fa-trash-o fa-fw"></span>
                    </button>
                </td>
            </tr>
        </tfoot>
    </table>
    <div class="col-md-12">
        <div id="sensorInstanceChangeMessage" class="alert alert-info" style="display: none;" role="alert">
            {{ lang._('After changing settings, press Save below to render the configuration and apply it.') }}
        </div>
    </div>
</div>

<div class="content-box" style="margin-top: 1em; padding-bottom: 1.5em;">

    {{ partial("layout_partials/base_form", ['fields': formDialogSensor, 'id': 'frm_sensor_settings']) }}

    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
        </button>
        <span class="pull-right">
            <b>{{ lang._('Service') }}:</b>
            <span id="sensor_status_pill" class="label label-default">{{ lang._('unknown') }}</span>
            {# The core service widget renders itself into this container.       #}
            {# On releases where the base layout already provides               #}
            {# #service_status_container in the page header, updateServiceControlUI() #}
            {# fills that one and this element is simply left empty. Either way #}
            {# the pill to its left is ours and is always populated, so the page #}
            {# is readable in both cases and there is nothing to verify.        #}
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
    <div class="col-md-12" style="margin-top: 1em;">
        <b>{{ lang._('Per instance') }}:</b>
        <span id="sensor_instance_states"></span>
    </div>
</div>

<div class="content-box" style="margin-top: 1em; padding-bottom: 1.5em;">
    <div class="col-md-12">
        <h3>
            {{ lang._('Diagnostics') }}
            <select id="sensor_instance_select" class="btn btn-default btn-xs">
                <option value="">{{ lang._('All instances') }}</option>
            </select>
            <button class="btn btn-default btn-xs" id="selftestAct" type="button">
                <i class="fa fa-stethoscope fa-fw"></i> {{ lang._('Run selftest') }}
                <i id="selftestAct_progress" class=""></i>
            </button>
            <button class="btn btn-default btn-xs sensor_instance_act" data-action="instanceStart" type="button">
                <i class="fa fa-play fa-fw"></i> {{ lang._('Start this one') }} <i class="act_progress"></i>
            </button>
            <button class="btn btn-default btn-xs sensor_instance_act" data-action="instanceStop" type="button">
                <i class="fa fa-stop fa-fw"></i> {{ lang._('Stop this one') }} <i class="act_progress"></i>
            </button>
            <button class="btn btn-default btn-xs sensor_instance_act" data-action="instanceRestart" type="button">
                <i class="fa fa-refresh fa-fw"></i> {{ lang._('Restart this one') }} <i class="act_progress"></i>
            </button>
        </h3>
        <p class="text-muted">
            {{ lang._('
                The selftest checks the binary, the _synapseids account, read access to /dev/bpf*, that each
                selected interface resolved to a device that exists, that each rendered configuration parses,
                that the token file is 0400, that the TLS material parses and that the certificate matches its
                key, and whether the daemon answers a TCP connect. One line per check, with the instance name
                in its own column. Read-only, and it prints no secrets. The same output is available on the
                console as
            ') }}
            <code>service synapseids_sensor selftest</code>
            {{ lang._('or, for one sensor,') }}
            <code>service synapseids_sensor selftest &lt;name&gt;</code>.
        </p>
        <pre id="sensor_selftest" style="max-height: 24em; overflow: auto;">{{ lang._('Press "Run selftest".') }}</pre>
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
            {{ lang._('
                Last 200 lines of /var/log/synapseids/&lt;instance&gt;/sensor.log, read through configd, for the
                instance selected above. Each sensor writes to its own file so that no line is ambiguous.
            ') }}
        </p>
        <pre id="sensor_log" style="max-height: 24em; overflow: auto;"></pre>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogInstance, 'id': 'DialogInstance', 'label': lang._('Edit sensor instance')]) }}
