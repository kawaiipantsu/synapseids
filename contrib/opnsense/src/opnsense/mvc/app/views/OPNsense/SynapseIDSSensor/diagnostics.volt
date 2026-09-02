{#
 # Copyright (C) 2026 SynapseIDS contributors
 # All rights reserved. BSD 2-Clause; see Sensor.php for the full text.
 #
 # SynapseIDS > Diagnostics (issue #178). The on-box selftest -- `synapse-sensor
 # doctor` per instance via the rc.d selftest verb and configd -- plus
 # per-instance start/stop/restart. Read-only checks; prints no secrets.
 #
 #   GET  /api/synapseidssensor/service/instances
 #   GET  /api/synapseidssensor/service/selftest[/<instance>]
 #   POST /api/synapseidssensor/service/{instanceStart,instanceStop,instanceRestart}/<instance>
 #}

<script>
    $( document ).ready(function() {

        function populateInstances() {
            ajaxGet('/api/synapseidssensor/service/instances', {}, function (data) {
                var rows = (data && data['instances']) ? data['instances'] : [];
                var $sel = $('#sensor_instance_select');
                var current = $sel.val();
                $sel.empty().append($('<option/>').val('').text('{{ lang._('All instances') }}'));
                $.each(rows, function (i, row) {
                    $sel.append($('<option/>').val(row['name']).text(row['name']));
                });
                if (current) { $sel.val(current); }
            });
        }

        function selectedInstance() {
            var v = $('#sensor_instance_select').val();
            return v ? '/' + encodeURIComponent(v) : '';
        }

        // `synapse-sensor doctor` per instance: reports the binary, the service
        // account, /dev/bpf* access, whether each interface resolved to a device
        // that exists, whether each rendered configuration parses, the token
        // mode, whether the TLS material parses and matches, and whether the
        // collector answers a TCP connect. One line per check.
        function runSensorSelftest() {
            $('#sensor_selftest').text('{{ lang._('Running the selftest...') }}');
            ajaxGet('/api/synapseidssensor/service/selftest' + selectedInstance(), {}, function (data) {
                var text = (data && data['output']) ? data['output'] : '';
                $('#sensor_selftest').text(text === ''
                    ? '{{ lang._('(the selftest produced no output -- is the plugin installed correctly?)') }}'
                    : text);
            });
        }

        $("#selftestAct").click(function () {
            $("#selftestAct_progress").addClass("fa fa-spinner fa-pulse");
            runSensorSelftest();
            $("#selftestAct_progress").removeClass("fa fa-spinner fa-pulse");
        });

        $(".sensor_instance_act").click(function () {
            var name = $('#sensor_instance_select').val();
            if (!name) { return; }
            var action = $(this).data('action');
            var $btn = $(this);
            $btn.find('i.act_progress').addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/synapseidssensor/service/" + action + "/" + encodeURIComponent(name), {}, function () {
                $btn.find('i.act_progress').removeClass("fa fa-spinner fa-pulse");
            });
        });

        $("#sensor_instance_select").change(function () {
            $('#sensor_selftest').text('{{ lang._('Press "Run selftest".') }}');
        });

        populateInstances();
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
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
                The same output is available on the console as
            ') }}
            <code>service synapseids_sensor selftest</code>
            {{ lang._('or, for one sensor,') }}
            <code>service synapseids_sensor selftest &lt;name&gt;</code>.
            {{ lang._('Read-only, and it prints no secrets.') }}
        </p>
        <pre id="sensor_selftest" style="max-height: 30em; overflow: auto;">{{ lang._('Press "Run selftest".') }}</pre>
    </div>
</div>
