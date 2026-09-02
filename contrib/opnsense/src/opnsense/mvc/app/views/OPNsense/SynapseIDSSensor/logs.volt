{#
 # Copyright (C) 2026 SynapseIDS contributors
 # All rights reserved. BSD 2-Clause; see Sensor.php for the full text.
 #
 # SynapseIDS > Logs (issue #178). The tail of each instance's sensor.log, read
 # through configd. How much a sensor writes here is the "Log level" control on
 # SynapseIDS > General.
 #
 #   GET /api/synapseidssensor/service/instances
 #   GET /api/synapseidssensor/service/log[/<instance>]   (token redacted)
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

        function refreshSensorLog() {
            $('#sensor_log').text('{{ lang._('Loading...') }}');
            ajaxGet('/api/synapseidssensor/service/log' + selectedInstance(), {}, function (data) {
                var text = (data && data['log']) ? data['log'] : '';
                $('#sensor_log').text(text === '' ? '{{ lang._('(the sensor log is empty)') }}' : text);
            });
        }

        $("#refreshLogAct").click(refreshSensorLog);
        $("#sensor_instance_select").change(refreshSensorLog);

        populateInstances();
        refreshSensorLog();
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    <div class="col-md-12">
        <h3>
            {{ lang._('Sensor log') }}
            <select id="sensor_instance_select" class="btn btn-default btn-xs">
                <option value="">{{ lang._('All instances') }}</option>
            </select>
            <button class="btn btn-default btn-xs" id="refreshLogAct" type="button">
                <i class="fa fa-refresh fa-fw"></i> {{ lang._('Refresh') }}
            </button>
        </h3>
        <p class="text-muted">
            {{ lang._('
                Last 200 lines of /var/log/synapseids/<instance>/sensor.log, read through configd, for the
                instance selected above. Each sensor writes to its own file so that no line is ambiguous. The
                verbosity is set by "Log level" on SynapseIDS > General.
            ') }}
        </p>
        <pre id="sensor_log" style="max-height: 30em; overflow: auto;"></pre>
    </div>
</div>
