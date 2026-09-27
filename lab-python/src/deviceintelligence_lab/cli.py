"""`di-lab` — the shell entry point. Three verbs cover the lab workflow:
gen-keys (server half), mint-chain (lab CA + pinned-roots.txt), issue-token
(a complete v1 token). Everything lands in the directory you point at."""
import argparse
import os

from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat)

from .chain import MintedChain
from .keys import new_server_keypair
from .tokens import TokenIssuer


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="di-lab",
        description="Mint DeviceIntelligence test chains and verdict tokens.")
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("gen-keys", help="generate the server X25519 keypair")
    keys.add_argument("--out", required=True, help="output directory")

    chain = sub.add_parser("mint-chain", help="mint the lab CA and pinned-roots.txt")
    chain.add_argument("--out", required=True, help="output directory")

    token = sub.add_parser("issue-token", help="issue one v1 verdict token")
    token.add_argument("--chain-dir", required=True, help="directory from mint-chain")
    token.add_argument("--session", default="lab-session", help="sessionId to embed")
    token.add_argument("--out", required=True, help="output directory")

    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    {"gen-keys": _gen_keys, "mint-chain": _mint_chain, "issue-token": _issue_token}[args.command](args)


def _gen_keys(args) -> None:
    server = new_server_keypair()
    _write(os.path.join(args.out, "server-private.pem"), server.private_pem)
    _write(os.path.join(args.out, "server-public.key"), server.public_raw)
    print(f"server-private.pem + server-public.key -> {args.out}/")


def _mint_chain(args) -> None:
    chain = MintedChain.mint()
    _write(os.path.join(args.out, "intermediate.pem"), chain.intermediate.public_bytes(Encoding.PEM))
    _write(os.path.join(args.out, "intermediate-key.pem"),
           chain.intermediate_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    _write(os.path.join(args.out, "root.pem"), chain.root.public_bytes(Encoding.PEM))
    _write(os.path.join(args.out, "pinned-roots.txt"), chain.pinned_roots_text.encode())
    print(f"lab CA + pinned-roots.txt -> {args.out}/  (pin the root in your verifier!)")


def _issue_token(args) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    intermediate = x509.load_pem_x509_certificate(
        _read(os.path.join(args.chain_dir, "intermediate.pem")))
    intermediate_key = load_pem_private_key(
        _read(os.path.join(args.chain_dir, "intermediate-key.pem")), password=None)
    pinned = _read(os.path.join(args.chain_dir, "pinned-roots.txt")).decode()
    chain = MintedChain(intermediate, intermediate_key,
                        x509.load_pem_x509_certificate(_read(os.path.join(args.chain_dir, "root.pem"))),
                        pinned)
    issued = TokenIssuer(chain).issue(session_id=args.session)
    _write(os.path.join(args.out, "token.hex"), issued.token_hex.encode())
    _write(os.path.join(args.out, "nonce.hex"), issued.nonce_hex.encode())
    print(f"token.hex + nonce.hex -> {args.out}/  (sessionId={args.session})")


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


if __name__ == "__main__":
    main()
