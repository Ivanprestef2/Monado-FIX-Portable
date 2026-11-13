"""Portable packager: the PE import-table reader and the DLL closure, with synthetic PE files (no game data)."""
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))
import make_portable as mp  # noqa: E402


def make_pe(imports, delay=(), pe32=False):
    """A minimal PE with one section (.idata) holding the import / delay-load tables."""
    raw_ptr, va = 0x400, 0x1000
    opt_size = 0xE0 if pe32 else 0xF0
    dirs_off = 96 if pe32 else 112
    # section layout: [import descriptors][delay descriptors][names]
    n_imp, n_del = len(imports) + 1, len(delay) + 1
    imp_off, del_off = 0, n_imp * 20
    names_off = del_off + n_del * 32
    names, blob = {}, b''
    for n in list(imports) + list(delay):
        names[n] = names_off + len(blob)
        blob += n.encode() + b'\0'
    sec = bytearray(names_off + len(blob))
    for i, n in enumerate(imports):
        struct.pack_into('<5I', sec, imp_off + i * 20, 0, 0, 0, va + names[n], 0)
    for i, n in enumerate(delay):
        struct.pack_into('<II', sec, del_off + i * 32, 1, va + names[n])
    sec[names_off:] = blob
    hdr = bytearray(raw_ptr)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3C, 0x80)
    pe = 0x80
    hdr[pe:pe + 4] = b'PE\0\0'
    struct.pack_into('<H', hdr, pe + 6, 1)           # sections
    struct.pack_into('<H', hdr, pe + 20, opt_size)   # size of optional header
    opt = pe + 24
    struct.pack_into('<H', hdr, opt, 0x10B if pe32 else 0x20B)
    struct.pack_into('<II', hdr, opt + dirs_off + 8, va + imp_off, n_imp * 20)
    struct.pack_into('<II', hdr, opt + dirs_off + 13 * 8, va + del_off, n_del * 32)
    s = opt + opt_size
    hdr[s:s + 8] = b'.idata\0\0'
    struct.pack_into('<IIII', hdr, s + 8, len(sec), va, len(sec), raw_ptr)
    return bytes(hdr) + bytes(sec)


class PeImports(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def w(self, name, data):
        p = os.path.join(self.d.name, name)
        with open(p, 'wb') as f:
            f.write(data)
        return p

    def test_reads_normal_and_delay_imports(self):
        for pe32 in (False, True):
            p = self.w('a.exe', make_pe(['SDL3.dll', 'KERNEL32.dll'], ['avcodec-61.dll'], pe32))
            self.assertEqual(mp.pe_imports(p), ['SDL3.dll', 'KERNEL32.dll', 'avcodec-61.dll'])

    def test_not_a_pe(self):
        self.assertEqual(mp.pe_imports(self.w('x.txt', b'hello' * 50)), [])
        self.assertEqual(mp.pe_imports(os.path.join(self.d.name, 'missing.dll')), [])

    def test_closure_follows_dependencies_and_skips_system(self):
        bin_dir = os.path.join(self.d.name, 'bin')
        os.makedirs(bin_dir)
        exe = self.w('game.exe', make_pe(['libA.dll', 'kernel32.dll', 'api-ms-win-crt-heap-l1-1-0.dll', 'vulkan-1.dll']))
        with open(os.path.join(bin_dir, 'libA.dll'), 'wb') as f:
            f.write(make_pe(['libB.dll', 'msvcrt.dll']))
        with open(os.path.join(bin_dir, 'LIBB.DLL'), 'wb') as f:
            f.write(make_pe([]))
        with open(os.path.join(bin_dir, 'vulkan-1.dll'), 'wb') as f:
            f.write(make_pe([]))
        found, missing = mp.collect_dlls([exe], [bin_dir], {'vulkan-1.dll'})
        self.assertEqual(sorted(found), ['liba.dll', 'libb.dll'])
        self.assertEqual(missing, [])

    def test_reports_missing(self):
        exe = self.w('game.exe', make_pe(['nowhere-1.dll']))
        found, missing = mp.collect_dlls([exe], [self.d.name], set())
        self.assertEqual(found, {})
        self.assertEqual(missing, ['nowhere-1.dll'])


class LauncherManifest(unittest.TestCase):
    def test_manifest_is_copied_to_the_top_of_the_folder(self):
        with tempfile.TemporaryDirectory() as out:
            mp.copy_launcher_manifest(out)
            self.assertTrue(os.path.isfile(os.path.join(out, 'recomplauncher.json')))

    def test_manifest_starts_the_exe_the_packager_puts_in_build(self):
        with open(os.path.join(mp.REPO, 'recomplauncher.json'), encoding='utf-8') as f:
            manifest = json.load(f)
        self.assertEqual(manifest['format'], 1)
        self.assertEqual(manifest['start']['program'], ['build/xcde.exe'])


if __name__ == '__main__':
    unittest.main()
