"""Command-line interface for File-Vault."""

import argparse
import getpass
import sys

from . import vault
from .encryption import DecryptionError
from .packer import PackError


def _prompt_password(confirm: bool) -> str:
    password = getpass.getpass("Password: ")
    if confirm:
        if password != getpass.getpass("Confirm password: "):
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
        description="Encrypt and decrypt files with AES-256-GCM.",
    )
    parser.add_argument(
        "--password",
        help="password (insecure: visible in shell history; prefer the prompt)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file into a .vault container")
    enc.add_argument("source", help="path to the file to encrypt")
    enc.add_argument("-o", "--output", help="output path (default: <source>.vault)")

    dec = sub.add_parser("decrypt", help="decrypt a .vault container")
    dec.add_argument("source", help="path to the .vault file to decrypt")
    dec.add_argument(
        "-o", "--output", help="output path (default: original file name)"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            password = _resolve_password(args.password, confirm=True)
            out = vault.encrypt_file(args.source, password, args.output)
            print(f"Encrypted -> {out}")
        elif args.command == "decrypt":
            password = _resolve_password(args.password, confirm=False)
            out = vault.decrypt_file(args.source, password, args.output)
            print(f"Decrypted -> {out}")
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 1
    except (DecryptionError, PackError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
