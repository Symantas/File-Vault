"""Command-line interface for File-Vault."""

import argparse
import getpass
import sys

from . import strength
from .cipher import AesGcmEncryptor
from .errors import VaultError
from .kdf import ScryptKeyDerivation
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


def _enforce_strength(password: str, allow_weak: bool) -> bool:
    """Return True if the password may be used; print reasons and False if not."""
    issues = strength.weaknesses(password)
    if issues and not allow_weak:
        print("error: weak password:", file=sys.stderr)
        for reason in issues:
            print(f"  - {reason}", file=sys.stderr)
        print("  (use --allow-weak to proceed anyway)", file=sys.stderr)
        return False
    return True


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
    enc.add_argument(
        "--allow-weak", action="store_true", help="allow a weak password"
    )

    info = sub.add_parser(
        "info", help="show a vault's format and KDF parameters (no password needed)"
    )
    info.add_argument("source", help="path to the .vault file to inspect")

    rekey = sub.add_parser(
        "rekey", help="change a vault's password (and optionally upgrade the KDF)"
    )
    rekey.add_argument("source", help="path to the .vault file to re-key")
    rekey.add_argument(
        "--new-password",
        help="new password (insecure: prefer the prompt)",
    )
    rekey.add_argument(
        "--scrypt",
        action="store_true",
        help="re-encrypt using the memory-hard scrypt KDF",
    )
    rekey.add_argument(
        "--allow-weak", action="store_true", help="allow a weak new password"
    )

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
            if not _enforce_strength(password, args.allow_weak):
                return 1
            out = service.encrypt_path(args.source, password, args.output)
            print(f"Encrypted -> {out}")
        elif args.command == "rekey":
            old_password = _resolve_password(args.password, confirm=False)
            new_password = _resolve_password(args.new_password, confirm=True)
            if not _enforce_strength(new_password, args.allow_weak):
                return 1
            new_encryptor = (
                AesGcmEncryptor(ScryptKeyDerivation()) if args.scrypt else None
            )
            out = service.rekey_path(
                args.source, old_password, new_password, new_encryptor=new_encryptor
            )
            print(f"Re-keyed -> {out}")
        elif args.command == "info":
            info = service.inspect(args.source)
            print(f"version:    {info.version}")
            print(f"kdf:        {info.kdf_algorithm}")
            print(f"key size:   {info.key_size * 8}-bit")
            params = ", ".join(f"{k}={v}" for k, v in info.parameters.items())
            print(f"parameters: {params}")
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
    except OSError as exc:
        target = exc.filename or args.source
        print(f"error: {target}: {exc.strerror}", file=sys.stderr)
        return 1
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
