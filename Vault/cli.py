"""Command-line interface for File-Vault."""

import argparse
import getpass
import sys

from .errors import VaultError
from .service import VaultService


def _prompt_password(confirm: bool) -> str:
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        print("error: passwords do not match", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("error: password must not be empty", file=sys.stderr)
        sys.exit(1)
    return password


def _resolve_password(arg_password: str | None, confirm: bool) -> str:
    """Use ``--password`` if given, otherwise prompt interactively."""
    if arg_password is not None:
        return arg_password
    return _prompt_password(confirm)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file-vault",
        description="Encrypt and decrypt files or folders with AES-256-GCM.",
    )
    parser.add_argument(
        "--password",
        help="password (insecure: visible in shell history; prefer the prompt)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser(
        "encrypt", help="encrypt a file or folder into a .vault container"
    )
    enc.add_argument("source", help="path to the file or folder to encrypt")
    enc.add_argument("-o", "--output", help="output path (default: <source>.vault)")

    dec = sub.add_parser("decrypt", help="decrypt a .vault container")
    dec.add_argument("source", help="path to the .vault file to decrypt")
    dec.add_argument(
        "-d",
        "--output-dir",
        help="directory to restore into (default: alongside the .vault file)",
    )
    dec.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="overwrite existing files when restoring",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    service = VaultService()

    try:
        if args.command == "encrypt":
            password = _resolve_password(args.password, confirm=True)
            out = service.encrypt_path(args.source, password, args.output)
            print(f"Encrypted -> {out}")
        elif args.command == "decrypt":
            password = _resolve_password(args.password, confirm=False)
            written = service.decrypt_path(
                args.source, password, args.output_dir, overwrite=args.force
            )
            print(f"Decrypted {len(written)} file(s):")
            for path in written:
                print(f"  {path}")
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 1
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
