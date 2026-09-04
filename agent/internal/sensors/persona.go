package sensors

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"strings"
)

// A Persona is everything a server says about itself, bundled so the parts
// cannot contradict each other. The values this replaces were five
// independent constants: a Samba server reporting an impossible Windows
// build, with its NetBIOS domain equal to its own computer name.
type Persona struct {
	ID           string
	NativeOS     string
	NativeLanMan string
	HasVersion   bool
	VerMajor     uint8
	VerMinor     uint8
	VerBuild     uint16
	DNSSuffix    string
}

const defaultPersonaID = "windows-server-2019"

// Build numbers are real releases. NativeOS/NativeLanMan follow the shape
// Windows actually sends ("<product> <build>" / "<product> 6.3").
var personas = []Persona{
	{
		ID:           "windows-server-2019",
		NativeOS:     "Windows Server 2019 Standard 17763",
		NativeLanMan: "Windows Server 2019 Standard 6.3",
		HasVersion:   true, VerMajor: 10, VerMinor: 0, VerBuild: 17763, DNSSuffix: "local",
	},
	{
		ID:           "windows-server-2022",
		NativeOS:     "Windows Server 2022 Standard 20348",
		NativeLanMan: "Windows Server 2022 Standard 6.3",
		HasVersion:   true, VerMajor: 10, VerMinor: 0, VerBuild: 20348, DNSSuffix: "local",
	},
	{
		ID:           "windows-11",
		NativeOS:     "Windows 11 Pro 22631",
		NativeLanMan: "Windows 11 Pro 6.3",
		HasVersion:   true, VerMajor: 10, VerMinor: 0, VerBuild: 22631, DNSSuffix: "local",
	},
	{
		// Real Samba sets no NTLMSSP_NEGOTIATE_VERSION and sends no
		// version structure. HasVersion false controls both.
		ID:           "samba-ubuntu-2204",
		NativeOS:     "Unix",
		NativeLanMan: "Samba 4.15.13-Ubuntu",
		HasVersion:   false, DNSSuffix: "lan",
	},
}

func Personas() []Persona { return personas }

func LookupPersona(id string) (Persona, bool) {
	for _, p := range personas {
		if p.ID == id {
			return p, true
		}
	}
	return Persona{}, false
}

// Identity is the resolved, per-sensor view every wire layer reads from.
type Identity struct {
	Persona     Persona
	NBDomain    string
	NBComputer  string
	DNSDomain   string
	DNSHostname string
	GUID        [16]byte
}

func netbios(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}

// Resolve never fails: a sensor that cannot name itself is worse than one
// that names itself plausibly. agent_id and agent_hostname are injected by
// the agent, not supplied by the operator.
func Resolve(cfg map[string]interface{}, kind string) Identity {
	p, _ := LookupPersona(defaultPersonaID)
	if want := str(cfg, "persona", ""); want != "" {
		if got, ok := LookupPersona(want); ok {
			p = got
		} else {
			log.Printf("[%s] unknown persona %q; falling back to %s", kind, want, defaultPersonaID)
		}
	}

	host := strings.TrimSpace(str(cfg, "hostname", ""))
	if host == "" {
		host = strings.TrimSpace(str(cfg, "agent_hostname", "honeypot"))
	}
	if host == "" {
		host = "honeypot"
	}
	domain := strings.TrimSpace(str(cfg, "domain", "WORKGROUP"))
	if domain == "" {
		domain = "WORKGROUP"
	}
	// The short host is what NetBIOS and DNS both want. os.Hostname() on a
	// cloud image routinely returns an FQDN ("ip-10-0-1-23.ec2.internal"),
	// and a NetBIOS name may not contain a dot — deriving NBComputer from
	// the full string advertised "IP-10-0-1-23.EC", truncated mid-label.
	shortHost := strings.SplitN(host, ".", 2)[0]

	id := Identity{
		Persona:    p,
		NBDomain:   netbios(domain),
		NBComputer: netbios(shortHost),
	}
	short := strings.ToLower(shortHost)
	if id.NBDomain != "WORKGROUP" {
		id.DNSDomain = strings.ToLower(domain) + "." + p.DNSSuffix
		id.DNSHostname = short + "." + id.DNSDomain
	} else {
		// A standalone machine has no DNS domain. Emitting
		// "workgroup.local" would be a tell of its own.
		id.DNSHostname = short
	}

	mac := hmac.New(sha256.New, []byte(str(cfg, "agent_id", "unenrolled")))
	mac.Write([]byte(kind))
	copy(id.GUID[:], mac.Sum(nil))
	return id
}
