package tsaudit_test

import (
	"testing"

	"mpegtsaudit/internal/tsaudit"
	"mpegtsaudit/internal/tsbuild"
)

// boundedFragment is a known-good stream for pes=bounded: PAT, PMT, then a
// 400-byte-body PES on the video PID (spans 3 TS packets) and a 200-byte-body
// PES on the audio PID (spans 2), bracketed by PCRs.
func boundedFragment() []byte {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 400)
	b.AddPES(b.Opt.Media[1].PID, 0xC0, 200)
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	return b.Bytes()
}

func TestBoundedPESAccepted(t *testing.T) {
	rep, err := tsaudit.AuditBoundedPES(boundedFragment(), 1000)
	if err != nil {
		t.Fatalf("bounded PES stream must pass: %v", err)
	}
	if len(rep.Media) != 2 {
		t.Fatalf("media entries = %d, want 2", len(rep.Media))
	}
	m0, m1 := rep.Media[0], rep.Media[1]
	if m0.PESCount == nil || *m0.PESCount != 1 || m0.PESBytes == nil || *m0.PESBytes != 406 {
		t.Errorf("video PES accounting wrong: %+v", m0)
	}
	if m1.PESCount == nil || *m1.PESCount != 1 || m1.PESBytes == nil || *m1.PESBytes != 206 {
		t.Errorf("audio PES accounting wrong: %+v", m1)
	}

	// The same stream is also legal under the base rules, with no PES fields.
	rep, err = tsaudit.Audit(boundedFragment(), 1000)
	if err != nil {
		t.Fatalf("base audit must accept the stream: %v", err)
	}
	if rep.Media[0].PESCount != nil || rep.Media[0].PESBytes != nil {
		t.Errorf("base audit must not report PES fields: %+v", rep.Media[0])
	}
}

func TestBoundedPESMultipleComplete(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 178) // exactly one 184-byte payload
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 400) // three packets
	b.AddPES(b.Opt.Media[1].PID, 0xC0, 200)
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	rep, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err != nil {
		t.Fatalf("back-to-back PES must pass: %v", err)
	}
	m0 := rep.Media[0]
	if *m0.PESCount != 2 || *m0.PESBytes != 184+406 {
		t.Errorf("video PES accounting wrong: count=%d bytes=%d", *m0.PESCount, *m0.PESBytes)
	}
}

func TestBoundedPESFirstPayloadWithoutPUSI(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // packet 3: payload with no PUSI
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESStartRequired {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESStartRequired, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESContinuationAfterCompletion(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 178) // packet 3 completes the PES
	b.AddPayload(b.Opt.Media[0].PID)        // packet 4: not a PUSI restart
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESStartRequired {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESStartRequired, err)
	}
	if err.Packet != 4 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 4 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESBadPrefix(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID)
	b.MutateLast(func(buf []byte) { buf[1] |= 0x40 }) // PUSI but pattern payload
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESBadPrefix {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESBadPrefix, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESZeroLength(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 0) // PES_packet_length = 0 is unbounded
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESZeroLength {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESZeroLength, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESHeaderShort(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	// PUSI packet whose adaptation field leaves only 3 payload bytes.
	pid := b.Opt.Media[0].PID
	pkt := make([]byte, tsbuild.PacketSize)
	pkt[0] = 0x47
	pkt[1] = 0x40 | byte(pid>>8)
	pkt[2] = byte(pid)
	pkt[3] = 0x30 // adaptation + payload, CC 0 (first packet on the PID)
	pkt[4] = 180  // adaptation_field_length -> 3 payload bytes remain
	pkt[5] = 0x00 // adaptation flags
	pkt[185], pkt[186], pkt[187] = 0x00, 0x00, 0x01
	b.AddRaw(pkt)
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESHeaderShort {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESHeaderShort, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESPrematureStart(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPESStart(b.Opt.Media[0].PID, 0xE0, 400) // packet 3: owes 222 more bytes
	b.AddPESStart(b.Opt.Media[0].PID, 0xE0, 400) // packet 4: PUSI too early
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESPrematureStart {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESPrematureStart, err)
	}
	if err.Packet != 4 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 4 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESTrailingBytes(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPESStart(b.Opt.Media[0].PID, 0xE0, 190) // packet 3: owes 12 more bytes
	b.AddPayload(b.Opt.Media[0].PID)             // packet 4: 184 bytes overshoot
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESTrailingBytes {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESTrailingBytes, err)
	}
	if err.Packet != 4 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 4 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESTruncated(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPESStart(b.Opt.Media[0].PID, 0xE0, 400) // packet 3: stream ends owing 222
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESTruncated {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESTruncated, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x101", err.Packet, err.PID)
	}
}

func TestBoundedPESMissing(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 178) // only the video PID carries a PES
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	_, err := tsaudit.AuditBoundedPES(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPESMissing {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESMissing, err)
	}
	if err.PID != 0x0102 {
		t.Errorf("pid = %#x, want 0x102 (audio PID without PES)", err.PID)
	}
}
