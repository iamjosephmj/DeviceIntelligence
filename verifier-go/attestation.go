package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// Minimal DER TLV reader (Der.kt port) — short/long/high-tag forms, exactly
// what the KeyDescription walk needs.

type derTlv struct {
	Tag   []byte
	Value []byte
}

var errDERTruncated = errors.New("DER truncated")

func readTlv(b []byte, i0 int) (derTlv, int, error) {
	i := i0
	if i >= len(b) {
		return derTlv{}, 0, errDERTruncated
	}
	start := i
	t := int(b[i] & 0xff)
	i++
	if t&0x1f == 0x1f { // high-tag-number form
		for i < len(b) && b[i]&0x80 != 0 {
			i++
		}
		i++
	}
	tag := b[start:i]
	if i >= len(b) {
		return derTlv{}, 0, errDERTruncated
	}
	n := int(b[i] & 0xff)
	i++
	length := n
	if n >= 0x80 {
		k := n & 0x7f
		if k == 0 || i+k > len(b) {
			return derTlv{}, 0, errDERTruncated
		}
		length = 0
		for j := 0; j < k; j++ {
			length = length<<8 | int(b[i+j]&0xff)
		}
		i += k
	}
	if i+length > len(b) {
		return derTlv{}, 0, errDERTruncated
	}
	return derTlv{Tag: tag, Value: b[i : i+length]}, i + length, nil
}

func tlvList(seq []byte) ([]derTlv, error) {
	out := []derTlv{}
	i := 0
	for i < len(seq) {
		tlv, next, err := readTlv(seq, i)
		if err != nil {
			return nil, err
		}
		out = append(out, tlv)
		i = next
	}
	return out, nil
}

func sequenceElements(der []byte) ([]derTlv, error) {
	outer, _, err := readTlv(der, 0)
	if err != nil {
		return nil, err
	}
	return tlvList(outer.Value)
}

// Android Key Attestation extension reader (Attestation.kt port).
// KeyDescription element indexes (spec §8): [1] attestationSecurityLevel
// (ENUMERATED), [4] attestationChallenge (OCTET STRING), [6]
// softwareEnforced, [7] teeEnforced — [7] preferred. AuthorizationList
// entries are context-tagged [704] = BF 85 40 (RootOfTrust).

const attestationOID = "1.3.6.1.4.1.11129.2.1.17"

var attestationOIDObj = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

var rootOfTrustTag = []byte{0xBF, 0x85, 0x40}

var (
	securityLevelNames = map[int]string{0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
	bootStateNames     = map[int]string{0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
)

type AttestationFields struct {
	SecurityLevel     *int
	VerifiedBootState *int
	DeviceLocked      *bool
}

func SecurityLevelName(level *int) string {
	if level == nil {
		return "?"
	}
	if n, ok := securityLevelNames[*level]; ok {
		return n
	}
	return itoa(*level)
}

func BootStateName(state *int) string {
	if state == nil {
		return "?"
	}
	if n, ok := bootStateNames[*state]; ok {
		return n
	}
	return itoa(*state)
}

func keyDescriptionDER(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(attestationOIDObj) {
			// ext.Value is the extnValue OCTET STRING content: the
			// KeyDescription SEQUENCE DER itself.
			return ext.Value, nil
		}
	}
	return nil, errors.New("no Android attestation extension on leaf")
}

func AttestationChallenge(leaf *x509.Certificate) ([]byte, error) {
	der, err := keyDescriptionDER(leaf)
	if err != nil {
		return nil, err
	}
	elems, err := sequenceElements(der)
	if err != nil {
		return nil, err
	}
	if len(elems) <= 4 {
		return nil, errors.New("KeyDescription too short")
	}
	return elems[4].Value, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
