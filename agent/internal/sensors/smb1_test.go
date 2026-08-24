package sensors

import "testing"

func TestSelectDialect(t *testing.T) {
	dialects := [][]byte{
		[]byte("\x02PC NETWORK PROGRAM 1.0"), []byte("\x02LANMAN1.0"),
		[]byte("\x02Windows for Workgroups 3.1a"), []byte("\x02LM1.2X002"),
		[]byte("\x02LANMAN2.1"), []byte("\x02NT LM 0.12"),
	}
	body := []byte{0}
	body = append(body, 0, 0)
	for _, d := range dialects {
		body = append(body, d...)
		body = append(body, 0)
	}
	body[1] = byte(len(body) - 2>>8)
	body[2] = byte(len(body) - 2)
	req := append(make([]byte, 32), body...)
	idx := selectDialectIndex(req)
	if idx != 5 {
		t.Fatalf("expected 5, got %d", idx)
	}
}
