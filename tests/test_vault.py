import json
import os
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pqcsuite import vault
from pqcsuite.pki import CA
from pqcsuite.vault import CHUNK, Identity, Recipient, VaultError


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.alice, self.bob, self.eve = Identity.generate(), Identity.generate(), Identity.generate()
        self.data = os.urandom(CHUNK * 2 + 12345)
        (self.d / "db.dump").write_bytes(self.data)

    def tearDown(self):
        self.tmp.cleanup()

    def enc(self, recipients=None, signer=None, src="db.dump"):
        out = self.d / "out.pqv"
        vault.encrypt(self.d / src, out, [r.public for r in recipients or [self.alice]], signer)
        return out

    def test_round_trip_for_each_recipient(self):
        f = self.enc([self.alice, self.bob])
        for who in (self.alice, self.bob):
            target, _ = vault.decrypt(f, self.d / who.public.id, who)
            self.assertEqual(target.read_bytes(), self.data)
        self.assertNotIn(self.data[:64], f.read_bytes())

    def test_output_paths_are_explained(self):
        with self.assertRaisesRegex(VaultError, "the folder .*nowhere does not exist"):
            vault.encrypt(self.d / "db.dump", self.d / "nowhere" / "db.pqv", [self.alice.public])
        f = self.enc()
        (self.d / "taken").write_text("ours")
        with self.assertRaisesRegex(VaultError, "taken is a file: give the folder"):
            vault.decrypt(f, self.d / "taken", self.alice)
        self.assertEqual((self.d / "taken").read_text(), "ours")

    def test_temporary_archive_names_never_follow_a_preexisting_symlink(self):
        victim = self.d / "keep.txt"
        victim.write_text("keep this")
        temporary = self.d / "out.pqv.part"
        try:
            temporary.symlink_to(victim)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        f = self.enc()
        self.assertEqual(victim.read_text(), "keep this")
        self.assertTrue(temporary.is_symlink())
        vault.add_recipients(f, self.alice, [self.bob.public])
        self.assertEqual(victim.read_text(), "keep this")
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(vault.decrypt(f, self.d / "restore", self.bob)[0].read_bytes(), self.data)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_plaintext_is_owner_only_during_and_after_restore(self):
        previous_umask = os.umask(0o022)
        self.addCleanup(os.umask, previous_umask)
        f = self.enc()
        original = vault.chunks

        def inspect_staging(*args):
            for chunk in original(*args):
                parts = list((self.d / "restore").glob(".pqv-partial-*"))
                self.assertEqual(len(parts), 1)
                self.assertEqual(parts[0].stat().st_mode & 0o077, 0)
                for p in parts[0].rglob("*") if parts[0].is_dir() else ():
                    if p.is_file():
                        self.assertEqual(p.stat().st_mode & 0o077, 0)
                yield chunk

        with mock.patch.object(vault, "chunks", side_effect=inspect_staging):
            target, _ = vault.decrypt(f, self.d / "restore", self.alice)
        self.assertEqual(target.stat().st_mode & 0o077, 0)
        src = self.d / "folder"
        src.mkdir()
        (src / "private.txt").write_bytes(self.data)
        target, _ = vault.decrypt(self.enc(src="folder"), self.d / "restore-dir", self.alice)
        self.assertEqual(target.stat().st_mode & 0o077, 0)

    def test_restore_preserves_a_dangling_destination_symlink(self):
        f = self.enc()
        out = self.d / "restore"
        out.mkdir()
        try:
            (out / "db.dump").symlink_to(out / "missing")
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        with self.assertRaisesRegex(VaultError, "already exists"):
            vault.decrypt(f, out, self.alice)
        self.assertTrue((out / "db.dump").is_symlink())

    def test_other_keys_cannot_open(self):
        with self.assertRaisesRegex(VaultError, "not encrypted for this key"):
            vault.decrypt(self.enc(), self.d / "x", self.eve)

    def test_any_modification_is_detected_and_nothing_is_written(self):
        f = self.enc()
        raw = bytearray(f.read_bytes())
        raw[len(raw) // 2] ^= 1
        f.write_bytes(bytes(raw))
        with self.assertRaisesRegex(VaultError, "modified"):
            vault.decrypt(f, self.d / "x", self.alice)
        self.assertFalse((self.d / "x").exists())

    def test_truncation_is_detected(self):
        f = self.enc()
        f.write_bytes(f.read_bytes()[:-(CHUNK // 2)])
        with self.assertRaisesRegex(VaultError, "truncated|modified"):
            vault.decrypt(f, self.d / "x", self.alice)

    def test_dropping_the_last_chunk_is_detected(self):
        f = self.enc()
        raw = f.read_bytes()
        (n,) = struct.unpack(">I", raw[5:9])
        pos = 9 + n
        for _ in range(2):
            (m,) = struct.unpack(">I", raw[pos:pos + 4])
            pos += 4 + m
        f.write_bytes(raw[:pos])
        with self.assertRaisesRegex(VaultError, "truncated"):
            vault.decrypt(f, self.d / "x", self.alice)

    def test_a_failed_encryption_leaves_nothing_behind(self):
        src = self.d / "site"
        src.mkdir()
        (src / "ok.bin").write_bytes(self.data)
        with mock.patch.object(tarfile.TarFile, "add", side_effect=OSError("disk read error")):
            with self.assertRaisesRegex(OSError, "disk read error"):
                vault.encrypt(src, self.d / "out.pqv", [self.alice.public])
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["db.dump", "site"])

    def test_folders_round_trip(self):
        src = self.d / "site"
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "b" / "x.txt").write_text("hello")
        (src / "top.bin").write_bytes(self.data)
        target, _ = vault.decrypt(self.enc(src="site"), self.d / "restore", self.alice)
        self.assertEqual((target / "a" / "b" / "x.txt").read_text(), "hello")
        self.assertEqual((target / "top.bin").read_bytes(), self.data)

    def test_links_leaving_the_folder_and_special_files_are_left_out_so_the_backup_restores(self):
        src = self.d / "site"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "a.txt").write_text("a")
        try:
            os.symlink("sub/a.txt", src / "inside")
            os.symlink("/etc/hosts", src / "absolute")
            os.symlink("../../outside", src / "sub" / "climbs")
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        if hasattr(os, "mkfifo"):
            os.mkfifo(src / "pipe")
        target, _ = vault.decrypt(self.enc(src="site"), self.d / "restore", self.alice)
        self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*")), ["inside", "sub", "sub/a.txt"])

    def test_every_single_bit_flip_is_refused(self):
        (self.d / "small.txt").write_text("statement 2026-09")
        f = self.d / "small.pqv"
        vault.encrypt(self.d / "small.txt", f, [self.alice.public, self.bob.public])
        raw = f.read_bytes()
        for i in range(len(raw)):
            m = bytearray(raw)
            m[i] ^= 1
            (self.d / "t.pqv").write_bytes(bytes(m))
            with self.subTest(byte=i), self.assertRaises(VaultError):
                vault.decrypt(self.d / "t.pqv", self.d / "o", self.alice)

    def test_removing_a_recipient_or_padding_the_signature_is_refused(self):
        ca = CA.init(self.d / "pki", "Root")
        out, _ = ca.issue("archive-job", "client")
        f = self.enc([self.alice, self.bob], vault.load_signer(out / "cert.pem", out / "key.pem"))
        raw = f.read_bytes()
        (n,) = struct.unpack(">I", raw[5:9])
        h = json.loads(raw[9:9 + n])
        h["recipients"] = [r for r in h["recipients"] if r["id"] == self.alice.public.id]
        header = json.dumps(h).encode()
        (self.d / "t.pqv").write_bytes(raw[:5] + struct.pack(">I", len(header)) + header + raw[9 + n:])
        with self.assertRaisesRegex(VaultError, "list of recipients was modified"):
            vault.decrypt(self.d / "t.pqv", self.d / "o", self.alice)
        i = raw.rindex(vault.SIG_MAGIC) + 4
        padded = raw[:i] + struct.pack(">I", struct.unpack(">I", raw[i:i + 4])[0] + 1) + raw[i + 4:]
        (self.d / "t.pqv").write_bytes(padded)
        with self.assertRaisesRegex(VaultError, "signature was modified"):
            vault.decrypt(self.d / "t.pqv", self.d / "o", self.alice)

    def test_failed_restore_leaves_no_folder_and_keys_are_named_clearly(self):
        f = self.enc()
        with self.assertRaises(VaultError):
            vault.decrypt(f, self.d / "nope", self.bob)
        self.assertFalse((self.d / "nope").exists())
        (self.d / "alice.pub").write_bytes(self.alice.public.pem())
        with self.assertRaisesRegex(VaultError, "not a vault private key"):
            Identity.load(self.d / "alice.pub")
        self.alice.save(self.d / "alice.key", None)
        with self.assertRaisesRegex(VaultError, "not a vault recipient key"):
            Recipient.load(self.d / "alice.key")
        self.alice.save(self.d / "locked.key", b"right")
        with self.assertRaisesRegex(VaultError, "wrong passphrase"):
            Identity.load(self.d / "locked.key", b"wrong")
        with self.assertRaisesRegex(VaultError, "needs its passphrase"):
            Identity.load(self.d / "locked.key")

    def test_signed_by_a_ca_certificate(self):
        ca = CA.init(self.d / "pki", "Root")
        out, _ = ca.issue("backup-server", "client")
        signer = vault.load_signer(out / "cert.pem", out / "key.pem")
        f = self.enc(signer=signer)
        _, who = vault.decrypt(f, self.d / "x", self.alice, ca=self.d / "pki" / "ca.crt", expected_signer="backup-server")
        self.assertEqual(who, "CN=backup-server")
        self.assertEqual(vault.inspect(f)["signed_by"], "CN=backup-server")
        evil, _ = ca.issue("evil,CN=backup-server", "client")
        f2 = self.d / "evil.pqv"
        vault.encrypt(self.d / "db.dump", f2, [self.alice.public], vault.load_signer(evil / "cert.pem", evil / "key.pem"))
        with self.assertRaisesRegex(VaultError, "expected CN=backup-server"):
            vault.decrypt(f2, self.d / "e", self.alice, ca=self.d / "pki" / "ca.crt", expected_signer="backup-server")

    def test_signature_length_is_bounded_before_reading_the_trailer(self):
        ca = CA.init(self.d / "pki", "Root")
        out, _ = ca.issue("archive-job", "client")
        f = self.enc(signer=vault.load_signer(out / "cert.pem", out / "key.pem"))
        raw = f.read_bytes()
        start = raw.rindex(vault.SIG_MAGIC) + len(vault.SIG_MAGIC)
        for length in (0, 1 << 17, (1 << 32) - 1):
            with self.subTest(length=length):
                f.write_bytes(raw[:start] + struct.pack(">I", length) + raw[start + 4:])
                with self.assertRaisesRegex(VaultError, "corrupted signature length"):
                    vault.verify(f, self.alice)
        for size in range(4):
            with self.subTest(size=size):
                f.write_bytes(raw[:start + size])
                with self.assertRaisesRegex(VaultError, "signature was modified or truncated"):
                    vault.verify(f, self.alice)

    def test_signature_cannot_be_stripped_or_faked(self):
        ca = CA.init(self.d / "pki", "Root")
        out, rec = ca.issue("backup-server", "client")
        f = self.enc(signer=vault.load_signer(out / "cert.pem", out / "key.pem"))
        raw = f.read_bytes()
        (n,) = struct.unpack(">I", raw[5:9])
        h = json.loads(raw[9:9 + n])
        del h["signer"]
        body = raw[9 + n:raw.rindex(vault.SIG_MAGIC)]
        header = json.dumps(h).encode()
        (self.d / "stripped.pqv").write_bytes(vault.MAGIC + struct.pack(">I", len(header)) + header + body)
        with self.assertRaises(VaultError):
            vault.decrypt(self.d / "stripped.pqv", self.d / "y", self.alice)
        other = CA.init(self.d / "other", "Other")
        with self.assertRaisesRegex(VaultError, "not issued by this CA"):
            vault.decrypt(f, self.d / "z", self.alice, ca=self.d / "other" / "ca.crt")
        ca.revoke(rec.serial)
        with self.assertRaisesRegex(VaultError, "revoked"):
            vault.decrypt(f, self.d / "w", self.alice, ca=self.d / "pki" / "ca.crt", crl=self.d / "pki" / "crl.pem")
        self.assertTrue(other)

    def test_unsigned_file_fails_when_a_signature_is_required(self):
        with self.assertRaisesRegex(VaultError, "not signed"):
            vault.decrypt(self.enc(), self.d / "x", self.alice, require_signature=True)

    def test_share_without_re_encrypting(self):
        f = self.enc()
        before = f.read_bytes()
        self.assertEqual(vault.add_recipients(f, self.alice, [self.bob.public]), 2)
        after = f.read_bytes()
        self.assertEqual(before[-1000:], after[-1000:])
        target, _ = vault.decrypt(f, self.d / "bob", self.bob)
        self.assertEqual(target.read_bytes(), self.data)
        with self.assertRaisesRegex(VaultError, "only share"):
            vault.add_recipients(f, self.eve, [self.eve.public])
        raw = bytearray(f.read_bytes())
        (n,) = struct.unpack(">I", raw[5:9])
        h = json.loads(raw[9:9 + n])
        h["recipients"][0]["key"] = h["recipients"][1]["key"]
        header = json.dumps(h).encode()
        (self.d / "bad.pqv").write_bytes(vault.MAGIC + struct.pack(">I", len(header)) + header + raw[9 + n:])
        with self.assertRaisesRegex(VaultError, "cannot unwrap"):
            vault.add_recipients(self.d / "bad.pqv", self.alice, [self.eve.public])
        self.assertFalse((self.d / "bad.pqv.part").exists())

    def test_cnsa2_suite(self):
        a, b = Identity.generate(cnsa2=True), Identity.generate(cnsa2=True)
        a.save(self.d / "a.key", None)
        (self.d / "a.pub").write_bytes(a.public.pem())
        a = Identity.load(self.d / "a.key")
        f = self.d / "c.pqv"
        vault.encrypt(self.d / "db.dump", f, [Recipient.load(self.d / "a.pub"), b.public])
        self.assertEqual(vault.inspect(f)["suite"], vault.CNSA2_SUITE)
        for who in (a, b):
            self.assertEqual(vault.decrypt(f, self.d / who.public.id, who)[0].read_bytes(), self.data)
        with self.assertRaisesRegex(VaultError, "not encrypted for this key"):
            vault.decrypt(f, self.d / "x", self.alice)
        with self.assertRaisesRegex(VaultError, "same suite"):
            vault.encrypt(self.d / "db.dump", self.d / "mixed.pqv", [a.public, self.alice.public])
        with self.assertRaisesRegex(VaultError, "suite"):
            vault.add_recipients(f, a, [self.bob.public])

    def test_identity_files_and_backups(self):
        other = self.d / "db.dump-logs"
        other.write_bytes(b"logs")
        vault.backup(other, self.d / "backups", [self.alice.public])
        self.alice.save(self.d / "alice.key", b"pw")
        (self.d / "alice.pub").write_bytes(self.alice.public.pem())
        loaded = Identity.load(self.d / "alice.key", b"pw")
        self.assertEqual(Recipient.load(self.d / "alice.pub").id, loaded.public.id)
        with self.assertRaises(VaultError):
            Identity.load(self.d / "alice.key", b"wrong")
        for _ in range(3):
            target, pruned = vault.backup(self.d / "db.dump", self.d / "backups", [loaded.public], keep=2)
        self.assertEqual(len(list((self.d / "backups").glob("db.dump-2*.pqv"))), 2)
        self.assertEqual(len(list((self.d / "backups").glob("db.dump-logs-*.pqv"))), 1, "retention must not touch other sources")
        self.assertEqual(len(pruned), 1)
        restored, _ = vault.decrypt(target, self.d / "restore", loaded)
        self.assertEqual(restored.read_bytes(), self.data)


if __name__ == "__main__":
    unittest.main()
