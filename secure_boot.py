"""Simulação didática de uma cadeia de confiança de Secure Boot."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class BootBlocked(ValueError):
    """Uma etapa da cadeia de confiança foi rejeitada."""


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def sign_record(record: dict, key) -> bytes:
    signature = key.sign(canonical(record), pss(), hashes.SHA256())
    return canonical({"record": record, "signature": base64.b64encode(signature).decode()})


def verify_record(envelope: bytes, key, role: str) -> dict:
    try:
        obj = json.loads(envelope)
        if set(obj) != {"record", "signature"}:
            raise ValueError("Envelope inválido")
        record = obj["record"]
        signature = base64.b64decode(obj["signature"], validate=True)
        key.verify(signature, canonical(record), pss(), hashes.SHA256())
        if record["version"] != 1 or record["role"] != role:
            raise ValueError("Versão ou papel inválido")
        return record
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise BootBlocked(f"Assinatura ou manifesto inválido: {role}") from exc


def load_public(data: bytes):
    try:
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
            raise ValueError("É necessária uma chave RSA de pelo menos 3072 bits")
        return key
    except (ValueError, TypeError) as exc:
        raise BootBlocked("Chave pública inválida") from exc


def provision(destination: Path) -> None:
    # Um diretório novo evita substituir chaves e artefatos existentes.
    destination.mkdir(parents=True, exist_ok=False)
    private = destination / "private"
    private.mkdir(mode=0o700)
    trust = destination / "trust"
    trust.mkdir()
    image = destination / "image"
    image.mkdir()
    root, loader = new_key(), new_key()
    for name, key in (("root", root), ("bootloader", loader)):
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        fd = os.open(private / f"{name}.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    root_pem, loader_pem = public_bytes(root.public_key()), public_bytes(loader.public_key())
    (trust / "root.pem").write_bytes(root_pem)
    (image / "bootloader.pem").write_bytes(loader_pem)
    bootloader = b"T4 simulated bootloader v1: authenticate kernel before execution\n"
    kernel = b'print("Kernel iniciado: cadeia de confianca validada.")\n'
    (image / "bootloader.bin").write_bytes(bootloader)
    (image / "kernel.py").write_bytes(kernel)
    (image / "bootloader.sig.json").write_bytes(sign_record({
        "version": 1, "role": "bootloader", "sha256": digest(bootloader),
        "kernel_key_sha256": digest(loader_pem),
    }, root))
    (image / "kernel.sig.json").write_bytes(sign_record({
        "version": 1, "role": "kernel", "sha256": digest(kernel),
    }, loader))


def verify_boot(image: Path, root_path: Path) -> tuple[bytes, list[str]]:
    """Retorna os próprios bytes autenticados; não reabre o kernel para executar."""
    events = []
    try:
        root = load_public(root_path.read_bytes())
        loader_record = verify_record((image / "bootloader.sig.json").read_bytes(), root, "bootloader")
        bootloader = (image / "bootloader.bin").read_bytes()
        if digest(bootloader) != loader_record["sha256"]:
            raise BootBlocked("Bootloader adulterado")
        events.append("Bootloader autenticado pela chave raiz")
        loader_pem = (image / "bootloader.pem").read_bytes()
        if digest(loader_pem) != loader_record["kernel_key_sha256"]:
            raise BootBlocked("Chave do bootloader não autorizada pela raiz")
        loader_key = load_public(loader_pem)
        events.append("Chave do bootloader autenticada")
        kernel_record = verify_record((image / "kernel.sig.json").read_bytes(), loader_key, "kernel")
        kernel = (image / "kernel.py").read_bytes()
        if digest(kernel) != kernel_record["sha256"]:
            raise BootBlocked("Kernel adulterado")
        events.append("Kernel autenticado pela chave do bootloader")
        return kernel, events
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, BootBlocked):
            raise
        raise BootBlocked(f"Não foi possível validar a cadeia: {exc}") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("init", help="Gerar chaves e uma imagem de demonstração assinada")
    demo.add_argument("destination", type=Path)
    boot = commands.add_parser("boot", help="Validar toda a cadeia antes de autorizar o boot")
    boot.add_argument("image", type=Path)
    boot.add_argument("--root-key", required=True, type=Path, help="Chave raiz confiável externa à imagem")
    boot.add_argument("--execute", action="store_true", help="Executar o kernel Python autenticado")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            provision(args.destination)
            print(f"Demonstração criada em {args.destination}")
            return 0
        kernel, events = verify_boot(args.image, args.root_key)
        for event in events:
            print(f"[OK] {event}")
        print("BOOT AUTORIZADO", flush=True)
        if args.execute:
            return subprocess.run([sys.executable, "-I", "-"], input=kernel, check=False).returncode
        return 0
    except (BootBlocked, OSError) as exc:
        print(f"{'BOOT BLOQUEADO' if args.command == 'boot' else 'ERRO'}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
