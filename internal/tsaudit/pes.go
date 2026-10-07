package tsaudit

// pesHeaderBytes is the fixed prefix every bounded PES starts with: the
// 3-byte packet_start_code_prefix, one stream_id byte and the 2-byte
// PES_packet_length field.
const pesHeaderBytes = 6

// pesTracker accumulates the bounded-PES state of one PMT media PID across
// TS packets. A PES must occupy whole TS payloads: it starts on a PUSI
// packet, runs over continuation packets of the same PID and ends exactly at
// a packet payload end.
type pesTracker struct {
	pid   int
	inPES bool
	owed  int   // payload bytes still owed by the in-progress PES
	total int   // declared size of the in-progress PES (header + body)
	count int   // complete PES packets seen
	bytes int64 // summed declared size of the complete PES packets
}

// consume validates one payload-bearing packet of the tracked PID against
// the bounded-PES rules and updates the running state.
func (t *pesTracker) consume(payload []byte, pusi bool, idx int) *AuditError {
	if pusi {
		if t.inPES {
			return auditError(ErrPESPrematureStart,
				"PUSI starts a new PES before the previous one completed", idx, t.pid)
		}
		if len(payload) < pesHeaderBytes {
			return auditError(ErrPESHeaderShort,
				"PUSI payload is shorter than the 6-byte PES header", idx, t.pid)
		}
		if payload[0] != 0x00 || payload[1] != 0x00 || payload[2] != 0x01 {
			return auditError(ErrPESBadPrefix,
				"PES does not start with the 00 00 01 prefix", idx, t.pid)
		}
		declared := int(payload[4])<<8 | int(payload[5])
		if declared == 0 {
			return auditError(ErrPESZeroLength,
				"PES_packet_length must be non-zero (bounded PES required)", idx, t.pid)
		}
		t.inPES = true
		t.total = pesHeaderBytes + declared
		t.owed = t.total
	} else if !t.inPES {
		return auditError(ErrPESStartRequired,
			"payload neither continues a PES nor starts one (PUSI not set)", idx, t.pid)
	}

	t.owed -= len(payload)
	if t.owed < 0 {
		return auditError(ErrPESTrailingBytes,
			"PES completes before the end of the packet payload", idx, t.pid)
	}
	if t.owed == 0 {
		t.inPES = false
		t.count++
		t.bytes += int64(t.total)
	}
	return nil
}

// finish validates the end-of-fragment state of the tracked PID. lastPkt is
// the index of the final packet in the fragment.
func (t *pesTracker) finish(lastPkt int) *AuditError {
	if t.inPES {
		return auditError(ErrPESTruncated,
			"fragment ends before the in-progress PES is complete", lastPkt, t.pid)
	}
	if t.count == 0 {
		return auditError(ErrPESMissing,
			"PMT media PID carries no complete PES", 0, t.pid)
	}
	return nil
}
