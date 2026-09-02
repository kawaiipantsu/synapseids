package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #178: the plugin UI is a top-level "SynapseIDS" side-menu section that
// expands to four pages, instead of one long scrolling settings page. These
// guards keep the menu, the controllers, the views and the routes in agreement
// so a rename in one place cannot silently 404 a menu entry.

const pluginApp = "../../contrib/opnsense/src/opnsense/mvc/app"

var submenuPages = []string{"sensors", "general", "logs", "diagnostics"}

func TestOPNsenseMenuIsASynapseIDSSubmenu(t *testing.T) {
	menu := readScript(t, pluginApp+"/models/OPNsense/SynapseIDSSensor/Menu/Menu.xml")

	if !strings.Contains(menu, "<SynapseIDS ") {
		t.Fatal("Menu.xml no longer declares a top-level <SynapseIDS> section (issue #178)")
	}
	// The old single Services entry must be gone: two menu entries pointing at
	// the same plugin is exactly the drift this restructure removes.
	if strings.Contains(menu, "<Services>") {
		t.Error("Menu.xml still adds a Services > entry alongside the SynapseIDS submenu")
	}
	for _, page := range submenuPages {
		want := `url="/ui/synapseidssensor/` + page + `"`
		if !strings.Contains(menu, want) {
			t.Errorf("Menu.xml has no child linking to %s", want)
		}
	}
}

func TestOPNsenseSubmenuPagesHaveControllerAndView(t *testing.T) {
	title := map[string]string{
		"sensors": "Sensors", "general": "General", "logs": "Logs", "diagnostics": "Diagnostics",
	}
	for _, page := range submenuPages {
		ctrlName := title[page] + "Controller.php"
		ctrl := readScript(t, filepath.Join(pluginApp, "controllers/OPNsense/SynapseIDSSensor", ctrlName))
		if !strings.Contains(ctrl, "class "+title[page]+"Controller extends IndexController") {
			t.Errorf("%s does not declare %sController extends IndexController", ctrlName, title[page])
		}
		if !strings.Contains(ctrl, `pick('OPNsense/SynapseIDSSensor/`+page+`')`) {
			t.Errorf("%s does not pick the %s view", ctrlName, page)
		}
		if _, err := os.Stat(filepath.Join(pluginApp, "views/OPNsense/SynapseIDSSensor", page+".volt")); err != nil {
			t.Errorf("view %s.volt is missing: %v", page, err)
		}
	}

	// The legacy /ui/synapseidssensor/settings route must still resolve, to the
	// Sensors page, so an existing bookmark does not break.
	legacy := readScript(t, filepath.Join(pluginApp, "controllers/OPNsense/SynapseIDSSensor/SettingsController.php"))
	if !strings.Contains(legacy, `pick('OPNsense/SynapseIDSSensor/sensors')`) {
		t.Error("SettingsController no longer forwards the legacy /settings URL to the Sensors page")
	}

	// index.volt was split into the four pages; it must not linger as a third
	// copy of the markup.
	if _, err := os.Stat(filepath.Join(pluginApp, "views/OPNsense/SynapseIDSSensor/index.volt")); err == nil {
		t.Error("index.volt still exists after the split into per-page views")
	}
}

func TestOPNsenseLogLevelSetting(t *testing.T) {
	model := readScript(t, pluginApp+"/models/OPNsense/SynapseIDSSensor/Sensor.xml")
	gStart := strings.Index(model, "<general>")
	gEnd := strings.Index(model, "<instances>")
	if gStart < 0 || gEnd < 0 || gEnd < gStart {
		t.Fatal("Sensor.xml has no <general> block before <instances>")
	}
	general := model[gStart:gEnd]
	if !strings.Contains(general, `<log_level type="OptionField">`) {
		t.Fatal("Sensor.xml <general> does not declare log_level as an OptionField")
	}
	for _, opt := range []string{"<errors>", "<normal>", "<verbose>"} {
		if !strings.Contains(general, opt) {
			t.Errorf("log_level is missing the %s option", strings.Trim(opt, "<>"))
		}
	}
	if !strings.Contains(general, "<default>normal</default>") {
		t.Error("log_level should default to normal so an upgrade needs no migration")
	}

	form := readScript(t, pluginApp+"/controllers/OPNsense/SynapseIDSSensor/forms/dialogSensor.xml")
	if !strings.Contains(form, "<id>sensor.general.log_level</id>") {
		t.Error("dialogSensor.xml does not surface log_level on the General page")
	}

	tmpl := readScript(t, "../../contrib/opnsense/src/opnsense/service/templates/OPNsense/SynapseIDSSensor/sensor-instance.conf")
	if !strings.Contains(tmpl, "--log-level ") || !strings.Contains(tmpl, "general['log_level']") {
		t.Error("sensor-instance.conf does not render --log-level from general.log_level")
	}
}
