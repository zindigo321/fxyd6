"""Bound ZIP reader with Windows-safe, selective extraction and streaming SHA."""
import csv
import hashlib
import io
from pathlib import Path, PureWindowsPath
import stat
import zipfile
from .common import EvidenceError, Unavailable, require, read, sha, write


def safe_name(name):
    # Reject alternate separators, ADS, device names and ambiguous Windows names.
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name, 'UNSAFE_MEMBER_PATH')
    require(not name.startswith('/') and not PureWindowsPath(name).is_absolute(), 'UNSAFE_MEMBER_PATH')
    parts = name.rstrip('/').split('/')
    reserved = {'con', 'prn', 'aux', 'nul'} | {f'{x}{i}' for x in ('com', 'lpt') for i in range(1, 10)}
    require(all(p not in {'', '.', '..'} and p == p.rstrip(' .') and p.split('.')[0].casefold() not in reserved for p in parts), 'UNSAFE_MEMBER_PATH')
    return '/'.join(parts)


def safe_inventory(infos):
    seen = set()
    for item in infos:
        name = safe_name(item.filename)
        require(name.casefold() not in seen, 'DUPLICATE_OR_CASE_COLLISION')
        seen.add(name.casefold())
        require(not stat.S_ISLNK(item.external_attr >> 16), 'LINK_MEMBER_REJECTED')
    return seen


class Archive:
    def __init__(self, config, vendor, check=lambda: None, extract=True):
        self.cfg, self.vendor, self.check = config, Path(vendor).resolve(), check
        self.extract = extract
        self.used = {}
        self.zip_path = Path(config['archive'])
        require(self.zip_path.stat().st_size == config['archive_bytes'], 'ARCHIVE_SIZE_MISMATCH')
        require(sha(self.zip_path, check) == config['archive_sha256'], 'ARCHIVE_SHA_MISMATCH')
        self.z = zipfile.ZipFile(self.zip_path)
        try:
            safe_inventory(self.z.infolist())
            require(len(self.z.infolist()) == config['archive_members'], 'ARCHIVE_MEMBER_COUNT')
            self.prefix = config['archive_root'] + '/'
            blob = self.z.read(self.prefix + 'MANIFEST.json')
            require(hashlib.sha256(blob).hexdigest() == config['manifest_sha256'], 'MANIFEST_SHA_MISMATCH')
            self.manifest = __import__('json').loads(blob)
            require(set(self.z.namelist()) == {self.prefix + n for n in self.manifest['files']} | {self.prefix + 'MANIFEST.json'}, 'MANIFEST_MEMBER_SET')
        except BaseException:
            self.z.close()
            raise

    def close(self):
        self.z.close()

    def path(self, name):
        self.check()
        safe_name(name)
        if name not in self.manifest['files']:
            raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: ' + name)
        target = (self.vendor / name).resolve()
        require(target.is_relative_to(self.vendor), 'EXTRACTION_OUTSIDE_VENDOR')
        expected = self.manifest['files'][name]
        if not target.exists():
            if not self.extract:
                raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: ' + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            with self.z.open(self.prefix + name) as src, target.open('xb') as dst:
                while block := src.read(1024 * 1024):
                    self.check()
                    h.update(block)
                    dst.write(block)
            observed = h.hexdigest()
        else:
            observed = sha(target, self.check)
        require(target.stat().st_size == expected['bytes'] and observed == expected['sha256'], 'MEMBER_BYTES_MISMATCH: ' + name)
        self.used[name] = dict(bytes=expected['bytes'], sha256=observed, origin=expected.get('origin'), source='archive_replay')
        return target

    def json(self, name):
        return read(self.path(name))

    def text(self, name):
        return self.path(name).read_text(encoding='utf-8-sig')

    def csv(self, name):
        with self.path(name).open(encoding='utf-8-sig', newline='') as stream:
            return list(csv.DictReader(stream))

    def preserve(self):
        for name, row in self.used.items():
            target = self.vendor / name
            require(target.stat().st_size == row['bytes'] and sha(target, self.check) == row['sha256'], 'MEMBER_CHANGED_AFTER_READ: ' + name)
        require(sha(self.zip_path, self.check) == self.cfg['archive_sha256'], 'ARCHIVE_CHANGED_AFTER_READ')
        return dict(status='PASS', actual_used_members=self.used, archive_sha256=self.cfg['archive_sha256'])
