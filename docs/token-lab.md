# The test-token lab

`deviceintelligence-lab` is the pip-installable counterpart to the verifier:
it mints attestation chains and issues verdict tokens so a backend can run
end-to-end tests without a real device. One package, three shell commands:

```bash
pip install -e lab-python

di-lab gen-keys --out keys/        # the server X25519 half
di-lab mint-chain --out ca/        # lab CA + pinned-roots.txt
di-lab issue-token --chain-dir ca/ --session smoke-1 --out token/
```

Point the verifier at the lab root and every issued token verifies:

```python
from deviceintelligence_verifier import TokenVerifier
from deviceintelligence_verifier.attestation.pinned_roots import _parse as parse_pinned

pinned = parse_pinned(open("ca/pinned-roots.txt").read())
result = TokenVerifier(pinned_roots=pinned).verify(open("token/token.hex").read(),
                                                   open("token/nonce.hex").read())
assert result.decision.value == "TRUSTWORTHY"
```

## What minting means

-   **The leaf is per-token.** The KeyDescription attestationChallenge must
    equal the token's nonce — that is the freshness check the verifier runs.
    The lab re-mints the leaf for every `issue-token` call; root and
    intermediate stay stable.

-   **Spoofed devices are one keyword away.** The TEE's word is just leaf
    options: `TokenIssuer(chain).issue(verified_boot_state=2,
    device_locked=False)` mints a token that is *authentic but COMPROMISED* —
    the exact two-layer verdict split the suite pins.

-   **Lab chains never pass against Google roots.** A minted chain terminates
    in YOUR lab root. Against the bundled pinned roots the verifier REJECTs
    it, and must. Pin `ca/pinned-roots.txt` or nothing verifies.

!!! warning "Lab tooling, never production trust"
    Minted chains are test fixtures, not hardware attestation. Nothing this
    package produces should ever be trusted where a real device's Keymaster
    chain is the trust anchor.

## The Python API

```python
from deviceintelligence_lab import MintedChain, TokenIssuer, new_server_keypair
from deviceintelligence_lab.tokens import seal_v2

chain = MintedChain.mint()
issued = TokenIssuer(chain).issue(session_id="login-attempt")

# v2 ECIES envelope (the current generation), opened with the server half:
server = new_server_keypair()
plaintext = TokenIssuer(chain).build_plaintext(session_id="login-attempt")
token = seal_v2(plaintext, server.public_raw)
```

## The parity gate

The lab's own suite drives `deviceintelligence-verifier` — every minted
artifact must grade identically to a real capture. The two packages are
pinned to each other's tests: `python -m pytest lab-python/tests`.
