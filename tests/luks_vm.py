"""Teste de integração interativo de uma VM já provisionada e desligada."""
import argparse
from contextlib import contextmanager
from getpass import getpass
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

import pexpect


VM = Path(__file__).resolve().parents[1] / "vm/luks"
EFI = Path("esp/EFI/BOOT/BOOTX64.EFI")
PROMPT = r"(?i)enter passphrase for [^:\r\n]+:"


@contextmanager
def boot(source, directory):
    shutil.copy2(source / "vars.fd", directory / "vars.fd")
    guest = pexpect.spawn(str(VM), ["boot", str(directory)], encoding="utf-8",
                          codec_errors="replace", echo=False, timeout=180)
    try:
        yield guest
    finally:
        guest.close(force=True)


def expect_firmware_rejection(source, directory, description):
    rejection = r"(?i)failed to load Boot[0-9a-f]{4} [^\r\n]*(?:Access Denied|Security Violation)"
    with boot(source, directory) as guest:
        for expected in (rejection, "No bootable option or device was found"):
            if guest.expect([expected, PROMPT]) == 1:
                raise SystemExit(f"O firmware iniciou a imagem {description}.")
    print(f"OK: o firmware recusou a imagem {description}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vm", type=Path)
    source = parser.parse_args().vm.resolve(strict=True)
    password = getpass("Senha LUKS da VM de teste: ")
    with tempfile.TemporaryDirectory(prefix=".t4-teste-", dir=source.parent) as tmp:
        copy = Path(tmp)
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--",
                        source / "root.luks", copy / "root.luks"], check=True)
        image = copy / EFI
        image.parent.mkdir(parents=True)
        unsigned = copy / "unsigned.efi"
        shutil.copy2(source / EFI, unsigned)
        subprocess.run(["sbattach", "--remove", unsigned], check=True)
        shutil.copy2(unsigned, image)
        expect_firmware_rejection(source, copy, "sem assinatura")

        key, cert = copy / "externa.key", copy / "externa.crt"
        subprocess.run(["openssl", "req", "-quiet", "-new", "-x509", "-newkey", "rsa:3072",
                        "-nodes", "-sha256", "-days", "1", "-subj", "/CN=T4 teste externo/",
                        "-keyout", key, "-out", cert], check=True)
        subprocess.run(["sbsign", "--key", key, "--cert", cert,
                        "--output", image, unsigned], check=True)
        subprocess.run(["sbverify", "--cert", cert, image], check=True)
        expect_firmware_rejection(source, copy, "assinada por certificado externo")

        shutil.copy2(source / EFI, image)
        with boot(source, copy) as guest:
            guest.expect(PROMPT)
            guest.sendline(secrets.token_hex(32))
            guest.expect_exact("No key available with this passphrase")
            guest.expect(PROMPT)
            print("OK: o LUKS recusou a senha incorreta.", flush=True)
            guest.sendline(password)
            result = guest.expect(["login:", "No key available with this passphrase"])
            if result == 1:
                raise SystemExit("Senha LUKS incorreta.")
        print("OK: a imagem assinada chegou ao login com a senha correta.")


if __name__ == "__main__":
    main()
