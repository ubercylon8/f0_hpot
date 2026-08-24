package sensors

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

// smbTransport abstracts message framing: classic NetBIOS-framed sessions
// (port 139 style, and clients like impacket that always wrap) versus raw
// SMB streams (port 445 style — samba's smbclient sends SMB directly on
// non-139 ports).
type smbTransport struct {
	conn net.Conn
	raw  bool
}

func newSMBTransport(conn net.Conn) *smbTransport {
	return &smbTransport{conn: conn}
}

// readHead reads the first 4 bytes and decides the framing mode.
// Returns the first complete message.
func (t *smbTransport) readHead() ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, head); err != nil {
		return nil, err
	}
	switch {
	case head[0] == 0x00:
		// NetBIOS session message: 3-byte big-endian length follows.
		length := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
		if length <= 0 || length > 64*1024 {
			return nil, errBadFrame
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(t.conn, buf); err != nil {
			return nil, err
		}
		return buf, nil
	case head[0] == 0xff || head[0] == 0xfe:
		// Raw SMB stream (445-style): no framing; accumulate until silence.
		t.raw = true
		return t.rawReadMessage(append([]byte{}, head...))
	default:
		return nil, errBadFrame
	}
}

// readMsg reads the next message using the detected framing.
func (t *smbTransport) readMsg() ([]byte, error) {
	if t.raw {
		return t.rawReadMessage(nil)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, head); err != nil {
		return nil, err
	}
	length := int(head[1])<<16 | int(head[2])<<8 | int(head[3])
	if length <= 0 || length > 64*1024 {
		return nil, errBadFrame
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(t.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// rawReadMessage accumulates bytes until a short silence or EOF, then
// truncates to the first complete SMB message in the buffer.
func (t *smbTransport) rawReadMessage(prefix []byte) ([]byte, error) {
	buf := prefix
	t.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	chunk := make([]byte, 4096)
	for len(buf) < 64*1024 {
		n, err := t.conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			break // timeout/EOF: work with what we have
		}
	}
	t.conn.SetReadDeadline(time.Time{}) // clear for next round
	if len(buf) < 4 {
		return nil, errBadFrame
	}
	return truncateToFirstMessage(buf)
}

// writeMsg writes a message using the detected framing.
func (t *smbTransport) writeMsg(msg []byte) error {
	t.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if t.raw {
		_, err := t.conn.Write(msg)
		return err
	}
	totalLen := len(msg)
	hdr := []byte{0x00, byte(totalLen >> 16), byte(totalLen >> 8), byte(totalLen)}
	_, err := t.conn.Write(append(hdr, msg...))
	return err
}

// truncateToFirstMessage computes the exact length of the first SMB message:
// SMB1: 32 + WordCount*2 + 2 + ByteCount; SMB2: per-command structure rules.
func truncateToFirstMessage(buf []byte) ([]byte, error) {
	if len(buf) < 36 {
		return buf, nil
	}
	switch {
	case buf[0] == 0xff && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B':
		wc := int(buf[32])
		if len(buf) < 35+wc*2 {
			return buf, nil
		}
		bc := int(binary.LittleEndian.Uint16(buf[33+wc*2 : 35+wc*2]))
		end := 35 + wc*2 + bc
		if end > len(buf) {
			end = len(buf)
		}
		return buf[:end], nil
	default: // SMB2
		if len(buf) < 68 {
			return buf, nil
		}
		cmd := binary.LittleEndian.Uint16(buf[12:14])
		structSize := int(binary.LittleEndian.Uint16(buf[4:6]))
		switch {
		case cmd == 0 && structSize == 36: // NEGOTIATE
			dialectCount := int(binary.LittleEndian.Uint16(buf[66:68]))
			end := 64 + 36 + 2*dialectCount
			if end > len(buf) {
				end = len(buf)
			}
			return buf[:end], nil
		case cmd == 1: // SESSION_SETUP: blob offset+length delimit the message
			if len(buf) < 84 {
				return buf, nil
			}
			off := int(binary.LittleEndian.Uint16(buf[76:78]))
			l := int(binary.LittleEndian.Uint16(buf[78:80]))
			end := off + l
			if end > len(buf) || end < 64 {
				end = len(buf)
			}
			return buf[:end], nil
		default:
			return buf, nil
		}
	}
}

var errBadFrame = conErr("bad SMB frame")

type conErr string

func (e conErr) Error() string { return string(e) }
