package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCTULabelOrientationAndCEST(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.csv")
	raw := "StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n2011/08/15 16:52:43.000000,10,tcp,192.0.2.1,12345,198.51.100.1,443,flow=From-Botnet\n2011/08/15 16:52:43.000000,10,tcp,198.51.100.1,443,192.0.2.1,12345,flow=To-Botnet\n"
	if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	labels, e := readLabels(path)
	if e != nil {
		t.Fatal(e)
	}
	if len(labels) != 1 {
		t.Fatal("To-Botnet must not become attack ground truth")
	}
	for _, rows := range labels {
		want := time.Date(2011, 8, 15, 14, 52, 43, 0, time.UTC)
		if rows[0].start != want || rows[0].label != "botnet_c2" {
			if !rows[0].start.Equal(want) {
				t.Fatal("CEST conversion mismatch")
			}
			if rows[0].label != "botnet_c2" {
				t.Fatal("label mismatch")
			}
		}
	}
}
