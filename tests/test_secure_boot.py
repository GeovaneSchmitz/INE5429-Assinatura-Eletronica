import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import secure_boot as sb


class SecureBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.template = Path(cls.workspace.name) / "template"
        sb.provision(cls.template)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        import shutil
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "case"
        shutil.copytree(self.template, self.base)
        self.image = self.base / "image"
        self.root = self.base / "trust/root.pem"

    def verify(self):
        return sb.verify_boot(self.image, self.root)

    def test_valid_chain(self):
        kernel, events = self.verify()
        self.assertEqual(kernel, (self.image / "kernel.py").read_bytes())
        self.assertEqual(len(events), 3)

    def test_tampered_components(self):
        for filename in ("bootloader.bin", "kernel.py"):
            with self.subTest(filename=filename):
                path = self.image / filename
                original = path.read_bytes()
                path.write_bytes(original + b"tampered")
                with self.assertRaises(sb.BootBlocked):
                    self.verify()
                path.write_bytes(original)

    def test_replaced_loader_key(self):
        (self.image / "bootloader.pem").write_bytes(self.root.read_bytes())
        with self.assertRaisesRegex(sb.BootBlocked, "não autorizada"):
            self.verify()

    def test_wrong_root(self):
        self.root.write_bytes((self.image / "bootloader.pem").read_bytes())
        with self.assertRaises(sb.BootBlocked):
            self.verify()

    def test_invalid_signatures_and_manifests(self):
        import json
        for filename in ("bootloader.sig.json", "kernel.sig.json"):
            path = self.image / filename
            original = path.read_bytes()
            changed = json.loads(original)
            changed["record"]["sha256"] = "0" * 64
            bad_signature = json.loads(original)
            bad_signature["signature"] = "AA=="
            for data in (b"invalid json", b"{}", sb.canonical(changed), sb.canonical(bad_signature)):
                with self.subTest(filename=filename, data=data):
                    path.write_bytes(data)
                    with self.assertRaises(sb.BootBlocked):
                        self.verify()
            path.write_bytes(original)

    def test_missing_files(self):
        for path in (*self.image.iterdir(), self.root):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(sb.BootBlocked):
                    self.verify()
                path.write_bytes(original)

    def test_invalid_root(self):
        self.root.write_bytes(b"not a public key")
        with self.assertRaises(sb.BootBlocked):
            self.verify()

    def test_wrong_role_even_with_valid_signature(self):
        key = sb.new_key()
        data = sb.sign_record({"version": 1, "role": "kernel"}, key)
        with self.assertRaises(sb.BootBlocked):
            sb.verify_record(data, key.public_key(), "bootloader")

    def test_no_execution_on_failure(self):
        (self.image / "kernel.py").write_bytes(b"print('UNTRUSTED')")
        with patch("secure_boot.subprocess.run") as run, contextlib.redirect_stderr(io.StringIO()):
            status = sb.main(["boot", str(self.image), "--root-key", str(self.root), "--execute"])
        self.assertEqual(status, 1)
        run.assert_not_called()

    def test_execute_verified_snapshot(self):
        expected = (self.image / "kernel.py").read_bytes()
        with patch("secure_boot.subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
            run.return_value.returncode = 0
            status = sb.main(["boot", str(self.image), "--root-key", str(self.root), "--execute"])
        self.assertEqual(status, 0)
        self.assertEqual(run.call_args.kwargs["input"], expected)

    def test_existing_destination_is_preserved(self):
        original = self.root.read_bytes()
        with self.assertRaises(FileExistsError):
            sb.provision(self.base)
        self.assertEqual(self.root.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
