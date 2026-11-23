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
def boot(directory):
    guest = pexpect.spawn(str(VM), ["boot", str(directory)], encoding="utf-8",
                          codec_errors="replace", echo=False, timeout=180)
    try:
        yield guest
    finally:
        guest.close(force=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vm", type=Path)
    source = parser.parse_args().vm.resolve(strict=True)
    password = getpass("Senha LUKS da VM de teste: ")
    with tempfile.TemporaryDirectory(prefix=".t4-teste-", dir=source.parent) as tmp:
        copy = Path(tmp)
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", "--",
                        source / "root.luks", copy / "root.luks"], check=True)
        shutil.copy2(source / "vars.fd", copy / "vars.fd")
        (copy / EFI).parent.mkdir(parents=True)
        shutil.copy2(source / EFI, copy / EFI)
        subprocess.run(["sbattach", "--remove", copy / EFI], check=True)
        with boot(copy) as guest:
            result = guest.expect([r"(?i)(?:Access Denied|Security Violation)", PROMPT])
            if result == 1:
                raise SystemExit("O firmware executou a imagem sem assinatura.")
        print("OK: o firmware recusou a imagem sem assinatura.", flush=True)

        shutil.copy2(source / "vars.fd", copy / "vars.fd")
        shutil.copy2(source / EFI, copy / EFI)
        with boot(copy) as guest:
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
