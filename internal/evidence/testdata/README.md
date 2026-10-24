These are literal authored synthetic histories, not observations of Kaferry.

The independent fixture author fixes source offsets 0,1,2,4, a proved control
span [3,4), two required distinct byte records, one forbidden aborted record,
and one permitted record. Both destination partitions are scanned. The valid
history reaches and recovers a process-kill fault before final output and saves.
Each invalid control changes the named property while retaining complete framing
unless truncation or identity corruption is itself the control. Checksums only
frame the fixture bytes; test expectations are declared independently in Go.

The unsafe-prefix control is a synthetic stand-in barrier: saved next offset 1
with no output before kill, followed by successful final recovery. It must remain
a violation even though the final membership is complete. Duplicate controls
have extra distinct destination positions, rather than duplicated scan events.

Identical-byte controls require aggregate multiplicity and disclose that replay
can mask loss of a particular indistinguishable occurrence. Full archive physical
checking is intentionally unsupported until M4.
