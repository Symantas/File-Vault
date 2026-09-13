"""Command-line interface for File-Vault."""

import argparse
import getpass
import os
import sys

from . import strength
from .errors import VaultError
from .identity import Identity, Recipient
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


def _write_identity_file(path: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="ascii") as fh:
        fh.write(text + "\n")


def _add_source(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument("source", help=help)


def _add_allow_weak(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument("--allow-weak", action="store_true", help=help)


def _add_scrypt(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scrypt", action="store_true", help="use the memory-hard scrypt KDF")


def _add_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--identity", help="identity key file to unlock with")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="file-vault",
        description="Encrypt files/folders with passwords and/or public-key recipients.",
    )
    parser.add_argument(
        "--password",
        help="password (insecure: visible in shell history; prefer the prompt)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an X25519 identity key pair")
    keygen.add_argument("-o", "--output", default="vault-identity.key", help="identity key file path")

    enc = sub.add_parser("encrypt", help="encrypt a file or folder into a .vault container")
    _add_source(enc, "path to the file or folder to encrypt")
    enc.add_argument("-o", "--output", help="output path (default: <source>.vault)")
    enc.add_argument("--recipient", action="append", metavar="PUB",
                     help="encrypt to a recipient public key (repeatable)")
    _add_scrypt(enc)
    _add_allow_weak(enc, "allow a weak password")

    info = sub.add_parser("info", help="show a vault's format and key slots (no password needed)")
    _add_source(info, "path to the .vault file to inspect")

    rekey = sub.add_parser("rekey", help="change a vault's password")
    _add_source(rekey, "path to the .vault file to re-key")
    rekey.add_argument("--new-password", help="new password (insecure: prefer the prompt)")
    _add_scrypt(rekey)
    _add_allow_weak(rekey, "allow a weak new password")

    addp = sub.add_parser("add-password", help="add another password to a vault")
    _add_source(addp, "path to the .vault file")
    addp.add_argument("--new-password", help="the password to add (insecure: prefer the prompt)")
    _add_identity(addp)
    _add_scrypt(addp)
    _add_allow_weak(addp, "allow a weak new password")

    addr = sub.add_parser("add-recipient", help="add a recipient public key to a vault")
    _add_source(addr, "path to the .vault file")
    addr.add_argument("--recipient", required=True, metavar="PUB", help="recipient public key")
    _add_identity(addr)

    rmslot = sub.add_parser("remove-slot", help="remove a key slot by index")
    _add_source(rmslot, "path to the .vault file")
    rmslot.add_argument("--index", type=int, required=True, help="slot index (see `info`)")

    dec = sub.add_parser("decrypt", help="decrypt a .vault container")
    _add_source(dec, "path to the .vault file to decrypt")
    _add_identity(dec)
    dec.add_argument("-d", "--output-dir",
                     help="directory to restore into (default: alongside the .vault file)")
    dec.add_argument("-f", "--force", action="store_true", help="overwrite existing files")

    return parser


def _print_info(info) -> None:
    print(f"version: {info.version}")
    print(f"slots:   {len(info.slots)}")
    for slot in info.slots:
        if slot.kdf_algorithm:
            params = ", ".join(f"{k}={v}" for k, v in slot.parameters.items())
            print(f"  [{slot.index}] {slot.type} ({slot.kdf_algorithm}: {params})")
        else:
            print(f"  [{slot.index}] {slot.type}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    kdf = ScryptKeyDerivation() if getattr(args, "scrypt", False) else None
    service = VaultService(default_kdf=kdf)

    try:
        if args.command == "keygen":
            identity = Identity.generate()
            _write_identity_file(args.output, identity.encode())
            print(f"Identity written -> {args.output}")
            print(f"Recipient: {identity.recipient().encode()}")
        elif args.command == "encrypt":
            recipients = tuple(Recipient.parse(r) for r in (args.recipient or ()))
            password = None
            if args.password is not None:
                password = args.password
            elif not recipients:
                password = _prompt_password(confirm=True)
            if password is not None and not _enforce_strength(password, args.allow_weak):
                return 1
            passwords = (password,) if password is not None else ()
            out = service.encrypt_path(
                args.source, passwords=passwords, recipients=recipients, destination=args.output
            )
            print(f"Encrypted -> {out}")
        elif args.command == "rekey":
            old_password = _resolve_password(args.password, confirm=False)
            new_password = _resolve_password(args.new_password, confirm=True)
            if not _enforce_strength(new_password, args.allow_weak):
                return 1
            out = service.rekey_path(args.source, old_password, new_password)
            print(f"Re-keyed -> {out}")
        elif args.command == "add-password":
            identity = Identity.load(args.identity) if args.identity else None
            unlock = None if identity else _resolve_password(args.password, confirm=False)
            new_password = _resolve_password(args.new_password, confirm=True)
            if not _enforce_strength(new_password, args.allow_weak):
                return 1
            out = service.add_password(
                args.source, new_password=new_password,
                unlock_password=unlock, unlock_identity=identity,
            )
            print(f"Added password slot -> {out}")
        elif args.command == "add-recipient":
            identity = Identity.load(args.identity) if args.identity else None
            unlock = None if identity else _resolve_password(args.password, confirm=False)
            out = service.add_recipient(
                args.source, recipient=Recipient.parse(args.recipient),
                unlock_password=unlock, unlock_identity=identity,
            )
            print(f"Added recipient slot -> {out}")
        elif args.command == "remove-slot":
            out = service.remove_slot(args.source, index=args.index)
            print(f"Removed slot {args.index} -> {out}")
        elif args.command == "info":
            _print_info(service.inspect(args.source))
        elif args.command == "decrypt":
            identity = Identity.load(args.identity) if args.identity else None
            password = args.password if identity else _resolve_password(args.password, confirm=False)
            written = service.decrypt_path(
                args.source, password=password, identity=identity,
                destination_dir=args.output_dir, overwrite=args.force,
            )
            print(f"Decrypted {len(written)} file(s):")
            for path in written:
                print(f"  {path}")
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 1
    except OSError as exc:
        target = exc.filename or getattr(args, "source", "?")
        print(f"error: {target}: {exc.strerror}", file=sys.stderr)
        return 1
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
