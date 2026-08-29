package sensors

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"time"
)

// CredSSP/NLA credential capture on top of TLS:
//
//  1. client sends TSRequest with SPNEGO NegTokenInit (NTLM NEGOTIATE)
//  2. server replies TSRequest carrying the NTLM CHALLENGE
//  3. client sends TSRequest with NTLM AUTHENTICATE -> captured
//
// We present a runtime-generated self-signed certificate. Real mstsc shows
// a cert warning; scripted attackers (hydra, crowbar, custom tooling)
// typically skip verification and hand over credentials.
func handleRDPCredSSP(tlsConn net.Conn, tokenID string, report Reporter) {
	defer tlsConn.Close()
	tlsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	tlsConn.SetWriteDeadline(time.Now().Add(15 * time.Second))

	// Held across CredSSP round trips: the AUTHENTICATE must be scored
	// against the challenge we issued, or the hashcat line is worthless.
	var serverChallenge [8]byte
	for round := 0; round < 3; round++ {
		req, err := readAllAvailable(tlsConn)
		if err != nil || len(req) == 0 {
			return
		}
		idx := indexOf(req, ntlmMagic)
		if idx < 0 {
			return
		}
		blob := req[idx:]
		switch {
		case IsNegotiate(blob):
			chalMsg, chal, err := BuildChallenge("FORTIKA-RDP")
			if err != nil {
				return
			}
			serverChallenge = chal
			if err := writeTSRequestChallenge(tlsConn, chalMsg); err != nil {
				return
			}
		case IsAuthenticate(blob):
			msg := findNTLMBlob(blob)
			auth, err := ParseAuthenticate(msg)
			if err != nil {
				log.Printf("[rdp] credssp parse failed from %s: %v", remoteIP(tlsConn), err)
				return
			}
			auth.Challenge = serverChallenge
			line := HashcatLine(auth)
			log.Printf("[rdp] captured credentials user=%q domain=%q from %s",
				auth.Username, auth.Domain, remoteIP(tlsConn))
			report(Trigger{
				Sensor:   "rdp",
				TokenID:  tokenID,
				Severity: "high",
				Detail: map[string]interface{}{
					"event":     "credssp_credentials",
					"source_ip": remoteIP(tlsConn),
					"username":  auth.Username,
					"domain":    auth.Domain,
					"host":      auth.Host,
					"hashcat":   line,
				},
				SeenAt: time.Now().UTC(),
			})
			return
		default:
			return
		}
	}
}

var cachedCert *tls.Certificate

func selfSignedCert() *tls.Certificate {
	if cachedCert != nil {
		return cachedCert
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "FORTIKA-RDP"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil
	}
	cachedCert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cachedCert
}

// upgradeRDPToTLS wraps an established RDP connection in TLS using our
// self-signed certificate. Returns nil if handshake fails (client rejected).
func upgradeRDPToTLS(raw net.Conn) net.Conn {
	cert := selfSignedCert()
	if cert == nil {
		return nil
	}
	tlsConn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[rdp] tls handshake failed from %s: %v", remoteIP(raw), err)
		return nil
	}
	return tlsConn
}

// readAllAvailable performs one pragmatic read of whatever the client sent
// (TSRequest DER frames are small; a single read suffices in practice).
func readAllAvailable(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	return buf[:n], nil
}

// writeTSRequestChallenge wraps an NTLM challenge in a minimal
// TSRequest/SPNEGO negTokenResp structure.
func writeTSRequestChallenge(w net.Conn, chal []byte) error {
	respTok := append([]byte{0x04, byte(len(chal))}, chal...)
	inner := append([]byte{0xa0, 0x03, 0x0a, 0x01, 0x00}, // negState: accept-completed
		append([]byte{0xa2, byte(len(respTok))}, respTok...)...)
	negResp := append([]byte{0x30, byte(len(inner))}, inner...) // SEQUENCE wrapper
	tsreq := append([]byte{
		0x30, byte(len(negResp) + 7), // SEQUENCE
		0xa0, 0x03, 0x02, 0x01, 0x05, // version = 5
		0xa1, byte(len(negResp)), // negTokenResp
	}, negResp...)
	_, err := w.Write(tsreq)
	return err
}
