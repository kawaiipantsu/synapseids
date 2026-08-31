package pcapoverip

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Classic-pcap magic numbers (little- and big-endian, microsecond and
// nanosecond timestamp resolution).
const (
	magicMicroLE = 0xa1b2c3d4
	magicMicroBE = 0xd4c3b2a1
	magicNanoLE  = 0xa1b23c4d
	magicNanoBE  = 0x4d3cb2a1

	// linkEN10MB and linkRAW are the two DLTs the SynapseIDS packet decoder
	// understands.
	linkEN10MB = 1
	linkRAW    = 101
)

// ErrNotClassicPCAP is returned by PcapFileStream when the file is not a classic
// .pcap capture (pcapng must be converted first with `editcap -F pcap`).
var ErrNotClassicPCAP = errors.New("pcapoverip: not a classic pcap file")

// PcapFileStream opens the classic-pcap file at path, validates its global
// header, and returns a StreamFunc that re-reads it from the start on every
// call, plus the file's link-layer type. speed scales the delay between records
// to their captured inter-arrival gaps: speed <= 0 replays with no pacing at
// all, 1 replays in real time, 2 twice as fast, and so on.
func PcapFileStream(path string, speed float64) (StreamFunc, uint32, error) {
	f, err := os.Open(path) //nolint:gosec // the operator names the capture to replay over the wire
	if err != nil {
		return nil, 0, fmt.Errorf("pcapoverip: %w", err)
	}
	defer func() { _ = f.Close() }()

	var g [24]byte
	if _, err := io.ReadFull(f, g[:]); err != nil {
		return nil, 0, ErrNotClassicPCAP
	}
	bo, nano, err := byteOrder(binary.LittleEndian.Uint32(g[0:4]))
	if err != nil {
		return nil, 0, err
	}
	link := bo.Uint32(g[20:24])
	if link != linkEN10MB && link != linkRAW {
		return nil, 0, fmt.Errorf("pcapoverip: unsupported pcap link type %d (want %d ethernet or %d raw)", link, linkEN10MB, linkRAW)
	}

	stream := func(ctx context.Context) (<-chan Record, <-chan error) {
		out := make(chan Record, 256)
		errc := make(chan error, 1)
		go replayFile(ctx, path, bo, nano, speed, out, errc)
		return out, errc
	}
	return stream, link, nil
}

func byteOrder(magic uint32) (binary.ByteOrder, bool, error) {
	switch magic {
	case magicMicroLE:
		return binary.LittleEndian, false, nil
	case magicNanoLE:
		return binary.LittleEndian, true, nil
	case magicMicroBE:
		return binary.BigEndian, false, nil
	case magicNanoBE:
		return binary.BigEndian, true, nil
	default:
		return nil, false, ErrNotClassicPCAP
	}
}

func replayFile(ctx context.Context, path string, bo binary.ByteOrder, nano bool, speed float64, out chan<- Record, errc chan<- error) {
	defer close(out)
	defer close(errc)

	f, err := os.Open(path) //nolint:gosec // path validated by PcapFileStream
	if err != nil {
		errc <- fmt.Errorf("pcapoverip: %w", err)
		return
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReaderSize(f, 1<<16)
	if _, err := io.CopyN(io.Discard, r, 24); err != nil {
		errc <- ErrNotClassicPCAP
		return
	}

	var (
		rec      [16]byte
		haveBase bool
		baseCap  time.Time
		baseWall time.Time
	)
	for {
		if ctx.Err() != nil {
			errc <- ctx.Err()
			return
		}
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return // clean end of capture
			}
			errc <- fmt.Errorf("pcapoverip: reading record header: %w", err)
			return
		}
		tsSec := bo.Uint32(rec[0:4])
		tsFrac := bo.Uint32(rec[4:8])
		inclLen := bo.Uint32(rec[8:12])
		if inclLen == 0 || inclLen > MaxFramePayload-8 {
			errc <- fmt.Errorf("pcapoverip: record length %d out of range", inclLen)
			return
		}
		buf := make([]byte, inclLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			errc <- fmt.Errorf("pcapoverip: short packet body: %w", err)
			return
		}
		nsec := int64(tsFrac) * 1000
		if nano {
			nsec = int64(tsFrac)
		}
		ts := time.Unix(int64(tsSec), nsec).UTC()

		if speed > 0 {
			if !haveBase {
				haveBase, baseCap, baseWall = true, ts, time.Now()
			} else if d := time.Duration(float64(ts.Sub(baseCap))/speed) - time.Since(baseWall); d > 0 {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					errc <- ctx.Err()
					return
				}
			}
		}

		select {
		case out <- Record{TS: ts, Raw: buf}:
		case <-ctx.Done():
			errc <- ctx.Err()
			return
		}
	}
}
