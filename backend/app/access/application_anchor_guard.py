"""Pin the exact local snapshot inputs before loading and throughout an operation.

Authenticated snapshot replay checks content. Stat pins detect replacement,
in-place writes, permission changes, hard links and directory additions during
that replay and every worker boundary without rehashing 568MB on each RPC.
"""
import os,stat
from pathlib import Path
from app.access.policy import require

class SourcePins:
    def __init__(self,paths):
        self.paths=tuple(Path(p) for p in paths);self.captured=self.capture()
    def capture(self):
        files=set()
        for path in self.paths:
            require(path.is_absolute() and not path.is_symlink())
            if path.is_dir():
                # Snapshot loaders read these attempts' immediate files only.
                files.add(path);files.update(path.iterdir())
            else:files.add(path)
        require(len(files)<=1000,'Source file bound')
        pins={}
        for path in files:
            require(not path.is_symlink());s=path.stat()
            require(s.st_uid==os.getuid() and not s.st_mode&0o077 and (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)),'Private source required')
            if stat.S_ISREG(s.st_mode):require(s.st_nlink==1,'Source hard link refused')
            pins[str(path)]=(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        return pins
    def check(self):require(self.capture()==self.captured,'Source input changed; stop and reconcile retained plans')
