{#
 # Copyright (C) 2026 SynapseIDS contributors
 # All rights reserved. BSD 2-Clause; see Sensor.php for the full text.
 #
 # SynapseIDS > General (issue #178). The settings there is exactly one of on
 # this firewall: the master enable, the transport posture (listen/connect), the
 # bearer token, the TLS material, and the shared log level. Form definition:
 # controllers/OPNsense/SynapseIDSSensor/forms/dialogSensor.xml.
 #
 #   GET  /api/synapseidssensor/settings/get
 #   POST /api/synapseidssensor/settings/set   (writes config.xml, re-renders
 #                                              every instance config, restarts)
 #}

<script>
    $( document ).ready(function() {
        var data_get_map = {'frm_sensor_settings': "/api/synapseidssensor/settings/get"};
        mapDataToFormUI(data_get_map).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        // settings/set writes config.xml AND re-renders every instance's
        // configuration, fixes permissions and restarts (or stops) the sensors -
        // no separate reconfigure call.
        $("#saveAct").click(function () {
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
            saveFormToEndpoint("/api/synapseidssensor/settings/set", 'frm_sensor_settings', function () {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
            }, true, function () {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
            });
        });
    });
</script>

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
    {{ partial("layout_partials/base_form", ['fields': formDialogSensor, 'id': 'frm_sensor_settings']) }}
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
        </button>
        <span class="text-muted" style="margin-left: 1em;">
            {{ lang._('Saving re-renders every sensor instance and restarts them. The instance list is on SynapseIDS > Sensors.') }}
        </span>
    </div>
</div>
