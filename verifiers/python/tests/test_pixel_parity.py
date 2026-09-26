"""Offline parity against a REAL token captured from the rooted Pixel 6 Pro
(KernelSU + TrickyStore). The Python verifier must grade this exact token+nonce
COMPROMISED, identically to the Kotlin reference."""
from pathlib import Path
from deviceintelligence_verifier.token_verifier import TokenVerifier

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def test_pixel_real_token_parity_compromised():
    token = (FIXTURES / "pixel-token.hex").read_text().strip()
    nonce = (FIXTURES / "pixel-nonce.hex").read_text().strip()
    res = TokenVerifier().verify(token, nonce)

    assert res.authentic
    assert not res.device_integrity_ok
    assert res.decision.value == "COMPROMISED"

    # The token is a registryVersion-1 capture: its attestation signal carries the
    # pre-reshuffle code, which the v2 table resolves to whatever row owns that
    # number today. A fresh device capture re-establishes end-to-end attribution.
    sig0 = next((s for s in res.signals if s.id == "INTEL_0000"), None)
    assert sig0 is not None and sig0.blocking

    checks = {c.name: c.ok for c in res.checks}
    assert checks["binding present"]
    assert checks["nonce matches issued"]
    assert checks["chain -> pinned Google root"]
    assert checks["signature over verdict"]
    assert not checks["verified boot state = Verified"]
