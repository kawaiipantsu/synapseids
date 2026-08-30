package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kawaiipantsu/synapseids/internal/api"
	"github.com/kawaiipantsu/synapseids/internal/capture"
	"github.com/kawaiipantsu/synapseids/internal/events"
	"github.com/kawaiipantsu/synapseids/internal/flow"
	"github.com/kawaiipantsu/synapseids/internal/inference"
	"github.com/kawaiipantsu/synapseids/internal/pipeline"
	"github.com/kawaiipantsu/synapseids/internal/storage"
)

// replayController runs at most one PCAP replay at a time through the shared
// pipeline, so replayed traffic reaches the UI exactly like live traffic would
// (PROJECT.md §6).
type replayController struct {
	bus     *events.Bus
	store   storage.Store
	rt      *inference.Runtime
	flowOpt flow.Options
	sensor  string
	flowID  *atomic.Uint64

	mu     sync.Mutex
	cancel context.CancelFunc
	src    capture.Source
	status api.ReplayStatus
}

func newReplayController(bus *events.Bus, store storage.Store, rt *inference.Runtime, fo flow.Options, sensor string, flowID *atomic.Uint64) *replayController {
	return &replayController{bus: bus, store: store, rt: rt, flowOpt: fo, sensor: sensor, flowID: flowID}
}

// Start opens path and begins replaying it at speed. It fails if a replay is
// already running.
func (c *replayController) Start(path string, speed capture.Speed) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.Running {
		return "", errors.New("a replay is already running; stop it first")
	}

	pf, err := capture.OpenPCAPFile(path)
	if err != nil {
		c.status.LastError = err.Error()
		return "", err
	}
	src := capture.NewReplay(pf, speed)
	ctx, cancel := context.WithCancel(context.Background())
	id := fmt.Sprintf("replay-%d", time.Now().UnixNano())

	c.cancel = cancel
	c.src = pf
	c.status = api.ReplayStatus{
		Running: true, ID: id, Source: path, Speed: speed.String(), Started: time.Now(),
	}
	c.bus.Publish(events.ReplayStarted, map[string]string{"id": id, "source": path, "speed": speed.String()})

	go c.progress(ctx, pf)
	go func() {
		st, runErr := pipeline.Run(ctx, src, c.rt, c.bus, c.store, pipeline.Options{
			Flow: c.flowOpt, Sensor: c.sensor, IDGen: func() uint64 { return c.flowID.Add(1) },
		})
		c.mu.Lock()
		c.status.Running = false
		c.status.Packets = st.Packets
		c.status.Flows = st.Flows
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			c.status.LastError = runErr.Error()
		}
		c.cancel = nil
		c.src = nil
		c.mu.Unlock()
		c.bus.Publish(events.ReplayFinished, map[string]any{
			"id": id, "packets": st.Packets, "flows": st.Flows,
			"classifications": st.Classifications, "elapsed_ms": st.ElapsedMS,
		})
	}()

	return id, nil
}

// Stop cancels a running replay. It is a no-op if nothing is running.
func (c *replayController) Stop() error {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	return nil
}

// Status returns a snapshot of the replay state.
func (c *replayController) Status() api.ReplayStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *replayController) progress(ctx context.Context, src capture.Source) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := src.Stats()
			c.mu.Lock()
			if c.status.Running {
				c.status.Packets = s.Decoded
				c.bus.Publish(events.ReplayProgress, map[string]any{
					"id": c.status.ID, "packets": s.Packets, "decoded": s.Decoded,
				})
			}
			c.mu.Unlock()
		}
	}
}
