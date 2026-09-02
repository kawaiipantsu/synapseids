{#
 # Copyright (C) 2026 SynapseIDS contributors
 # All rights reserved. BSD 2-Clause; see Sensor.php for the full text.
 #
 # SynapseIDS > Sensors (issue #178). The capture-instance grid: one
 # synapse-sensor process per interface. Split out of the old single index.volt;
 # the shared transport/credential settings are on SynapseIDS > General, the log
 # tail on SynapseIDS > Logs and the selftest on SynapseIDS > Diagnostics.
 #
 # Endpoints used here:
 #   *    /api/synapseidssensor/settings/{search,get,add,set,del,toggle}Instance
 #   POST /api/synapseidssensor/settings/set          (Apply: re-render + restart)
 #   POST /api/synapseidssensor/service/{start,stop,restart}
 #   GET  /api/synapseidssensor/service/status
 #   GET  /api/synapseidssensor/service/instances
 #}

<script>
    $( document ).ready(function() {

        $("#grid-instances").UIBootgrid({
            search: '/api/synapseidssensor/settings/searchInstance/',
            get:    '/api/synapseidssensor/settings/getInstance/',
            set:    '/api/synapseidssensor/settings/setInstance/',
            add:    '/api/synapseidssensor/settings/addInstance/',
            del:    '/api/synapseidssensor/settings/delInstance/',
            toggle: '/api/synapseidssensor/settings/toggleInstance/'
        });

        // The core service widget reduces N processes to one word; with one
        // sensor stopped and the rest running it says "stopped", which is
        // pessimistic but safe. The per-instance badges below it are the real
        // picture and name every instance.
        function refreshSensorStatus() {
            updateServiceControlUI('synapseidssensor');
            ajaxGet('/api/synapseidssensor/service/status', {}, function (data) {
                var state = (data && data['status']) ? data['status'] : 'unknown';
                var cls = 'label-warning';
                if (state === 'running') { cls = 'label-success'; }
                else if (state === 'stopped') { cls = 'label-danger'; }
                else if (state === 'disabled') { cls = 'label-default'; }
                $('#sensor_status_pill')
                    .removeClass('label-success label-danger label-warning label-default')
                    .addClass(cls).text(state);
            });
            refreshInstanceBadges();
        }

        function refreshInstanceBadges() {
            ajaxGet('/api/synapseidssensor/service/instances', {}, function (data) {
                var rows = (data && data['instances']) ? data['instances'] : [];
                var $box = $('#sensor_instance_states').empty();
                if (rows.length === 0) {
                    $box.append($('<span class="text-muted"/>').text(
                        '{{ lang._('No sensor instances are configured. Add one per interface above.') }}'));
                    return;
                }
                $.each(rows, function (i, row) {
                    var cls = 'label-default';
                    if (row['state'] === 'running') { cls = 'label-success'; }
                    else if (row['state'] === 'stopped') { cls = 'label-danger'; }
                    else if (row['state'] === 'unknown') { cls = 'label-warning'; }
                    var text = row['name'] + ': ' + row['state'];
                    if (row['enabled'] && !row['authorized']) {
                        text = text + ' (not authorised)';
                        cls = 'label-danger';
                    }
                    $box.append($('<span/>').addClass('label ' + cls)
                        .css('margin-right', '0.5em').text(text));
                });
            });
        }

        // Grid rows save themselves through the *Instance endpoints, which do
        // NOT re-render or restart anything. Apply calls settings/set, the single
        // place the whole reconfigure cycle runs.
        $("#applyAct").click(function () {
            $("#applyAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/synapseidssensor/settings/set", {}, function () {
                $("#applyAct_progress").removeClass("fa fa-spinner fa-pulse");
                refreshSensorStatus();
            });
        });

        $(".sensor_service_act").click(function () {
            var action = $(this).data('action');
            var $btn = $(this);
            $btn.find('i.act_progress').addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/synapseidssensor/service/" + action, {}, function () {
                $btn.find('i.act_progress').removeClass("fa fa-spinner fa-pulse");
                refreshSensorStatus();
            });
        });

        // Surface an unmigrated single-sensor configuration (see the old
        // index.volt note): the settings are still in config.xml, one command
        // brings them back as an instance.
        ajaxGet('/api/synapseidssensor/settings/get', {}, function (data) {
            var legacy = (data && data['sensor'] && data['sensor']['general'])
                ? data['sensor']['general']['interface'] : '';
            if (legacy) { $('#sensor_migration_warning').show(); }
        });

        refreshSensorStatus();
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
    {{ lang._('then reload this page.') }}
</div>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="col-md-12">
        <h3>{{ lang._('Sensor instances') }}</h3>
        <p class="text-muted">
            {{ lang._('
                One synapse-sensor process per interface. Each instance has its own sensor identity, its own
                rendered configuration, its own pidfile and its own log, so a packet routed between two
                monitored segments is reported twice by two named sensors instead of two observations
                collapsing into one flow. Adding or editing a row does not apply it: press Apply.
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
            {{ lang._('After changing instances, press Apply to render the configuration and restart the sensors.') }}
        </div>
        <hr/>
        <button class="btn btn-primary" id="applyAct" type="button">
            <b>{{ lang._('Apply') }}</b> <i id="applyAct_progress" class=""></i>
        </button>
        <span class="pull-right">
            <b>{{ lang._('Service') }}:</b>
            <span id="sensor_status_pill" class="label label-default">{{ lang._('unknown') }}</span>
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

{{ partial("layout_partials/base_dialog", ['fields': formDialogInstance, 'id': 'DialogInstance', 'label': lang._('Edit sensor instance')]) }}
