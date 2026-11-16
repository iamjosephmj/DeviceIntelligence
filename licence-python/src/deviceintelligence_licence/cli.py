"""`di-licence` — the shell entry point, mirroring
tools/keys/gen-dev-licence.py: one keypair, two files."""
import argparse

from .keys import generate_licence


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="di-licence",
        description="Mint the DeviceIntelligence RVN2 server.key asset and backend private PEM.")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="generate a dev licence + keypair")
    gen.add_argument("application_id", help="the Android applicationId the licence binds to")
    gen.add_argument("out_dir", help="output directory")
    gen.add_argument("--epoch", type=int, default=0, help="rotation counter 0..255 (default 0)")
    gen.add_argument("--not-after", type=int, default=0, help="expiry, epoch seconds; 0 = never")
    args = parser.parse_args(argv)

    material = generate_licence(args.application_id, epoch=args.epoch,
                                not_after=args.not_after, out_dir=args.out_dir)
    import os
    print(f"app      : {args.application_id}")
    print(f"epoch    : {args.epoch}   notAfter: {args.not_after or 'never'}")
    print(f"asset    : {os.path.join(args.out_dir, 'server.key')}  (PUBLIC — ships in the APK)")
    print(f"private  : {os.path.join(args.out_dir, f'server-priv-{args.epoch}.pem')}  (backend half)")
    print(f"pubkey   : {material.public_raw_hex}")


if __name__ == "__main__":
    main()
