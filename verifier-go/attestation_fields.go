package verifier

import "crypto/x509"

// AttestationFields — the TEE's own account of the device (spec §8).
func AttestationFieldsOf(leaf *x509.Certificate) (*AttestationFields, error) {
	der, err := keyDescriptionDER(leaf)
	if err != nil {
		return nil, err
	}
	elems, err := sequenceElements(der)
	if err != nil {
		return nil, err
	}
	f := &AttestationFields{}
	if len(elems) > 1 && len(elems[1].Value) > 0 {
		v := int(elems[1].Value[0] & 0xff)
		f.SecurityLevel = &v
	}

	// teeEnforced [7] preferred over softwareEnforced [6]; both are plain
	// SEQUENCEs whose entries carry the context tags.
	for _, idx := range []int{7, 6} {
		if len(elems) <= idx || f.VerifiedBootState != nil {
			continue
		}
		entries, err := tlvList(elems[idx].Value)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if string(entry.Tag) != string(rootOfTrustTag) {
				continue
			}
			rot, err := tlvList(entry.Value)
			if err != nil {
				break
			}
			if len(rot) > 1 && len(rot[1].Value) > 0 {
				locked := rot[1].Value[0]&0xff != 0
				f.DeviceLocked = &locked
			}
			if len(rot) > 2 && len(rot[2].Value) > 0 {
				state := int(rot[2].Value[0] & 0xff)
				f.VerifiedBootState = &state
			}
			break
		}
	}
	return f, nil
}
