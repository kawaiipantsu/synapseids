package api

import (
	"encoding/json"
	"math"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/obs"
	"github.com/kawaiipantsu/synapseids/internal/registry"
	"github.com/kawaiipantsu/synapseids/internal/schema"
	"github.com/kawaiipantsu/synapseids/internal/training"
)

const metricDetailCap = 100

// writeMLMetrics reads in-memory stores only. It never loads a bundle, scans a
// dataset CSV, or parses training history beyond the latest reported epoch.
func (s *Server) writeMLMetrics(p *obs.Writer) {
	if s.workbench != nil {
		jobs, online := s.workbench.List()
		p.GaugeInt("synapseids_training_worker_online", "1 when the workbench worker has a fresh heartbeat.", boolToInt(online))
		counts := map[string]int64{}
		for _, j := range jobs {
			counts[j.Status]++
		}
		for _, state := range []string{"queued", "running", "completed", "failed", "cancelled"} {
			p.GaugeInt("synapseids_training_jobs", "Workbench job count by bounded lifecycle state.", counts[state], obs.Label{Name: "status", Value: state})
		}
	}
	{
		attacks, apps, rich, legacy := s.metrics.BehaviorSnapshot()
		for i, c := range schema.AttackV2().Classes {
			p.Counter("synapseids_neural_threat_classifications_total", "Detailed neural threat classifications; snapshot updates count separately.", attacks[i], obs.Label{Name: "class", Value: c.Name})
		}
		for i, c := range schema.ApplicationV1().Classes {
			p.Counter("synapseids_neural_application_classifications_total", "Independent neural application classifications; absent application models increment nothing.", apps[i], obs.Label{Name: "application", Value: c.Name})
		}
		p.Counter("synapseids_behavior_inputs_total", "Classified vectors by packet-metadata availability.", rich, obs.Label{Name: "coverage", Value: "rich"})
		p.Counter("synapseids_behavior_inputs_total", "Classified vectors by packet-metadata availability.", legacy, obs.Label{Name: "coverage", Value: "legacy"})
	}
	loaded := map[string]int{"classifier": 0, "anomaly": 0, "sequence": 0, "application": 0}
	if s.rt != nil {
		loaded["classifier"] = len(s.rt.Models())
		loaded["anomaly"] = len(s.rt.AnomalyModels())
		loaded["sequence"] = len(s.rt.SequenceModels())
		if s.rt.ApplicationModel() != nil {
			loaded["application"] = 1
		}
	}
	for _, family := range []string{"classifier", "anomaly", "sequence", "application"} {
		p.GaugeInt("synapseids_models_loaded", "Models loaded in the inference runtime, by scoring role.", int64(loaded[family]), obs.Label{Name: "role", Value: family})
	}
	entries := []registry.Entry{}
	if s.reg != nil {
		entries = s.reg.List()
	}
	p.GaugeInt("synapseids_models_registered", "Model bundles in the registry.", int64(len(entries)))
	for i, e := range entries {
		if i >= metricDetailCap {
			break
		}
		labels := []obs.Label{{Name: "model_id", Value: e.ModelID}, {Name: "family", Value: e.Family}}
		p.GaugeInt("synapseids_model_parameters", "Registered model parameter count; newest 100 registry entries.", e.ParameterCount, labels...)
		p.GaugeInt("synapseids_model_artifact_bytes", "Registered bundle artifact size in bytes; newest 100 entries.", e.ArtifactBytes, labels...)
		p.GaugeInt("synapseids_model_active", "1 when this registered model is active; newest 100 entries.", boolToInt(e.Status == registry.StatusActive), labels...)
		p.GaugeInt("synapseids_model_input_features", "Registered model input width; newest 100 entries.", int64(e.InputSize), labels...)
	}
	var versions, rows int64
	var bytes int64
	if s.ds != nil {
		for _, d := range s.ds.List() {
			versions++
			rows += int64(d.FlowCount)
			bytes += d.CSVBytes
		}
	}
	p.GaugeInt("synapseids_dataset_versions", "Dataset versions in the dataset manager.", versions)
	p.GaugeInt("synapseids_dataset_rows", "Sum of rows across all dataset versions; versions can contain overlapping flows.", rows)
	p.GaugeInt("synapseids_dataset_csv_bytes", "Sum of CSV sizes across all dataset versions.", bytes)

	runs := []training.Run{}
	if s.tr != nil {
		runs = s.tr.List()
	}
	counts := map[training.Status]int{}
	for _, r := range runs {
		counts[r.Status]++
	}
	for _, state := range []training.Status{training.StatusRunning, training.StatusCompleted, training.StatusFailed, training.StatusStale} {
		p.GaugeInt("synapseids_training_runs", "Known training runs by current status, including stale running workers.", int64(counts[state]), obs.Label{Name: "status", Value: string(state)})
	}
	p.GaugeInt("synapseids_training_detail_limit", "Maximum newest training runs and model entries exported with individual labels.", metricDetailCap)
	for i, r := range runs {
		if i >= metricDetailCap {
			break
		}
		labels := []obs.Label{{Name: "run_id", Value: r.ID}}
		p.GaugeInt("synapseids_training_epoch", "Latest reported epoch of a training run.", int64(r.Epoch), labels...)
		p.GaugeInt("synapseids_training_epochs_planned", "Planned epoch budget; early stopping can finish before it is reached.", int64(r.EpochsTotal), labels...)
		for _, state := range []training.Status{training.StatusRunning, training.StatusCompleted, training.StatusFailed, training.StatusStale} {
			ls := append(append([]obs.Label{}, labels...), obs.Label{Name: "status", Value: string(state)})
			p.GaugeInt("synapseids_training_run_status", "One-hot current training run status.", boolToInt(r.Status == state), ls...)
		}
		for _, item := range []struct{ name, help, at string }{
			{"synapseids_training_started_timestamp_seconds", "Training registration Unix timestamp.", r.StartedAt},
			{"synapseids_training_updated_timestamp_seconds", "Last training update Unix timestamp; compare with time() for worker freshness.", r.UpdatedAt},
			{"synapseids_training_finished_timestamp_seconds", "Terminal training update Unix timestamp; absent until finished.", r.FinishedAt},
		} {
			if at, err := time.Parse(time.RFC3339Nano, item.at); err == nil {
				p.Gauge(item.name, item.help, float64(at.UnixNano())/1e9, labels...)
			}
		}
		if len(r.History) == 0 {
			continue
		}
		var latest map[string]json.RawMessage
		if json.Unmarshal(r.History[len(r.History)-1], &latest) != nil {
			continue
		}
		// Fixed allowlist: arbitrary reporter keys never become metric names or
		// labels. Missing/string/nonfinite values are omitted, never zero-filled.
		for _, item := range []struct{ key, name, help string }{
			{"train_loss", "synapseids_training_loss", "Latest reported training loss."},
			{"val_loss", "synapseids_training_validation_loss", "Latest reported validation loss."},
			{"val_accuracy", "synapseids_training_validation_accuracy_ratio", "Latest reported validation accuracy, 0..1; not live detection accuracy."},
			{"val_macro_precision", "synapseids_training_validation_precision_ratio", "Latest reported validation macro precision, 0..1."},
			{"val_macro_recall", "synapseids_training_validation_recall_ratio", "Latest reported validation macro recall, 0..1."},
			{"val_macro_f1", "synapseids_training_validation_f1_ratio", "Latest reported validation macro F1, 0..1."},
			{"val_recon_error", "synapseids_training_reconstruction_error", "Latest reported validation reconstruction error for anomaly training."},
			{"lr", "synapseids_training_learning_rate", "Latest reported optimizer learning rate."},
			{"elapsed_s", "synapseids_training_elapsed_seconds", "Latest reported worker elapsed training seconds."},
			{"batches", "synapseids_training_batches_processed", "Batches processed in the latest reported epoch; a gauge, not a lifetime counter."},
			{"batches_total", "synapseids_training_batches_planned", "Batch budget of the latest reported epoch."},
		} {
			raw := latest[item.key]
			if len(raw) == 0 || string(raw) == "null" {
				continue
			}
			var value float64
			if json.Unmarshal(raw, &value) == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
				p.Gauge(item.name, item.help, value, labels...)
			}
		}
	}
}

func (s *Server) writeSensorMetrics(p *obs.Writer) {
	if s.sensors == nil {
		return
	}
	for _, sensor := range s.sensors.Sensors() {
		// Stable sensor/source identity, never remote address, session ID,
		// filter, location, or credentials. Counters reset on reconnect.
		labels := []obs.Label{{Name: "sensor", Value: sensor.SourceName}, {Name: "mode", Value: sensor.Mode}}
		p.Counter("synapseids_sensor_records_total", "Flow/feature records received in the current sensor connection; resets on reconnect.", sensor.Records, labels...)
		p.Counter("synapseids_sensor_record_bytes_total", "Serialized flow/feature payload bytes received; not observed network bandwidth.", sensor.RecordBytes, labels...)
		p.Counter("synapseids_sensor_packets_total", "Raw packet frames received from a sensor; zero in flow/feature mode.", sensor.Packets, labels...)
		p.Counter("synapseids_sensor_packet_bytes_total", "Raw packet bytes received from a sensor; zero in flow/feature mode.", sensor.Bytes, labels...)
		p.Counter("synapseids_sensor_capture_drops_total", "Capture drops reported for this sensor source, not firewall blocks.", sensor.Drops, labels...)
		p.GaugeInt("synapseids_sensor_running", "1 when the connected sensor is running.", boolToInt(sensor.State == "running"), labels...)
	}
}
