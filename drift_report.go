package main

import (
	"path/filepath"
	"runtime"
	"time"

	"github.com/s-b-repo/cau-kernel/internal/kstate"
)

type driftReport struct {
	SchemaVersion  string              `json:"schema_version"`
	SensorVersion  string              `json:"sensor_version"`
	ObservedAt     time.Time           `json:"observed_at"`
	Scope          string              `json:"scope"`
	BootID         string              `json:"boot_id,omitempty"`
	BaselineStatus string              `json:"baseline_status"`
	Coverage       string              `json:"coverage"`
	AlertCount     int                 `json:"alert_count"`
	InfoCount      int                 `json:"info_count"`
	WarningCount   int                 `json:"warning_count"`
	UnknownPosture int                 `json:"unknown_posture_count"`
	Hooks          []driftHookCoverage `json:"hooks"`
}

type driftHookCoverage struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
}

func summarizeDrift(root string, verified bool, snapshot kstate.Snapshot, changes []kstate.Change) driftReport {
	report := driftReport{
		SchemaVersion: "1", SensorVersion: version, ObservedAt: time.Now().UTC(),
		Scope: "fixture", BaselineStatus: "unsigned", Coverage: "complete",
		WarningCount: len(snapshot.Warnings), Hooks: make([]driftHookCoverage, 0, len(snapshot.Hooks)),
	}
	if runtime.GOOS == "linux" && filepath.Clean(root) == "/" {
		report.Scope = "live"
		id, err := (kstate.Collector{Root: root}).BootID()
		if err != nil || id == "" {
			report.Coverage = "partial"
		} else {
			report.BootID = id
		}
	}
	if verified {
		report.BaselineStatus = "verified"
	}
	for _, hook := range snapshot.Hooks {
		report.Hooks = append(report.Hooks, driftHookCoverage{Kind: hook.Kind, State: hook.State})
		if hook.State != kstate.HookReadable {
			report.Coverage = "partial"
		}
	}
	for _, observation := range snapshot.Posture.Observations {
		if observation.Level == "unknown" {
			report.UnknownPosture++
		}
	}
	for _, change := range changes {
		if change.Severity == "alert" {
			report.AlertCount++
		} else {
			report.InfoCount++
		}
		if change.Kind == "hook-coverage" {
			report.Coverage = "partial"
		}
	}
	if report.WarningCount > 0 || report.UnknownPosture > 0 || len(report.Hooks) == 0 {
		report.Coverage = "partial"
	}
	return report
}
