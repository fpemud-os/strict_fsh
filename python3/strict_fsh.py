#!/usr/bin/env python3

# strict_fsh.py - strict file system hierarchy
#
# Copyright (c) 2020-2021 Fpemud <fpemud@sina.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
strict_fsh

@author: Fpemud
@license: GPLv3 License
@contact: fpemud@sina.com
"""

import os
import pwd
import grp
import glob
import stat
import filecmp

__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


class FshCheckError(Exception):
    pass


class FileSystemHierarchy:

    """We comply with FHS (https://refspecs.linuxfoundation.org/fhs.shtml) but have some extra rules:
         1. Fedora UsrMerge (https://fedoraproject.org/wiki/Features/UsrMove)
         2. optional toolchain directories in /usr
         3. optional swap file /var/swap.dat
    """

    def __init__(self, dirPrefix="/"):
        self._dirPrefix = dirPrefix
        self._record = set()

    def get_file_list(self):
        ret = []

        ret.append("/bin")

        ret.append("/boot")

        ret.append("/dev")

        ret.append("/etc")

        ret.append("/etc/passwd")
        ret.append("/etc/group")
        ret.append("/etc/shadow")
        ret.append("/etc/gshadow")
        ret.append("/etc/subuid")
        ret.append("/etc/subgid")
        if self._exists("/etc/passwd-"):
            ret.append("/etc/passwd-")
        if self._exists("/etc/group-"):
            ret.append("/etc/group-")
        if self._exists("/etc/shadow-"):
            ret.append("/etc/shadow-")
        if self._exists("/etc/gshadow-"):
            ret.append("/etc/gshadow-")
        if self._exists("/etc/subuid-"):
            ret.append("/etc/subuid-")
        if self._exists("/etc/subgid-"):
            ret.append("/etc/subgid-")

        ret.append("/home")
        for fn in self._glob("/home/*"):
            ret.append(fn)

        ret.append("/lib")
        ret.append("/lib64")

        ret.append("/mnt")

        if self._exists("/opt"):
            ret.append("/opt")
            if self._exists("/opt/bin"):
                ret.append("/opt/bin")

        ret.append("/proc")

        ret.append("/root")

        ret.append("/run")

        ret.append("/sbin")

        ret.append("/sys")

        ret.append("/tmp")

        ret.append("/usr")

        ret.append("/usr/bin")

        if self._exists("/usr/games"):
            ret.append("/usr/games")
            if self._exists("/usr/games/bin"):
                ret.append("/usr/games/bin")

        if self._exists("/usr/include"):
            ret.append("/usr/include")

        ret.append("/usr/lib")
        ret.append("/usr/lib64")
        ret.append("/usr/libexec")

        if self._exists("/usr/local"):
            ret.append("/usr/local")
            if self._exists("/usr/local/bin"):
                ret.append("/usr/local/bin")
            if self._exists("/usr/local/etc"):
                ret.append("/usr/local/etc")
            if self._exists("/usr/local/games"):
                ret.append("/usr/local/games")
            if self._exists("/usr/local/include"):
                ret.append("/usr/local/include")
            if self._exists("/usr/local/lib"):
                ret.append("/usr/local/lib")
            if self._exists("/usr/local/lib64"):
                ret.append("/usr/local/lib64")
            if self._exists("/usr/local/man"):
                ret.append("/usr/local/man")
            if self._exists("/usr/local/sbin"):
                ret.append("/usr/local/sbin")
            if self._exists("/usr/local/share"):
                ret.append("/usr/local/share")
            if self._exists("/usr/local/src"):
                ret.append("/usr/local/src")

        ret.append("/usr/share")

        if self._exists("/usr/src"):
            ret.append("/usr/src")

        for fn in self._glob("/usr/*"):
            if self._isToolChainName(os.path.basename(fn)):
                ret.append(fn)

        ret.append("/var")
        if self._exists("/var/cache"):
            ret.append("/var/cache")
        if self._exists("/var/db"):
            ret.append("/var/db")
        if self._exists("/var/empty"):
            ret.append("/var/empty")
        if self._exists("/var/games"):
            ret.append("/var/games")
        if self._exists("/var/lib"):
            ret.append("/var/lib")
        if self._exists("/var/lock"):
            ret.append("/var/lock")
        if self._exists("/var/log"):
            ret.append("/var/log")
        if self._exists("/var/run"):
            ret.append("/var/run")
        if self._exists("/var/spool"):
            ret.append("/var/spool")
        if self._exists("/var/swap.dat"):
            ret.append("/var/swap.dat")
        if True:
            ret.append("/var/tmp")

        return ret

    def check(self):
        self._check(False)

    def fixate(self):
        self._check(True)

    def _check(self, bAutoFix):
        self._bAutoFix = bAutoFix
        self._record = set()

        # /bin
        self._checkSymlink("/bin", "usr/bin")

        # /boot
        self._checkDir("/boot")
        self._checkEntryMetadata("/boot", 0o0755, "root", "root")

        # /dev
        self._checkDir("/dev")
        self._checkEntryMetadata("/dev", 0o0755, "root", "root")

        # /etc
        self._checkDir("/etc")
        self._checkEntryMetadata("/etc", 0o0755, "root", "root")

        # /etc/passwd
        self._checkFile("/etc/passwd")
        self._checkEntryMetadata("/etc/passwd", 0o0644, "root", "root")

        # /etc/group
        self._checkFile("/etc/group")
        self._checkEntryMetadata("/etc/group", 0o0644, "root", "root")

        # /etc/shadow
        self._checkFile("/etc/shadow")
        self._checkEntryMetadata("/etc/shadow", 0o0640, "root", "root")

        # /etc/gshadow
        self._checkFile("/etc/gshadow")
        self._checkEntryMetadata("/etc/gshadow", 0o0640, "root", "root")

        # /etc/subuid
        self._checkFile("/etc/subuid")
        self._checkEntryMetadata("/etc/subuid", 0o0644, "root", "root")

        # /etc/subgid
        self._checkFile("/etc/subgid")
        self._checkEntryMetadata("/etc/subgid", 0o0644, "root", "root")

        # /etc/passwd-
        if self._exists("/etc/passwd-"):
            self._checkFile("/etc/passwd-")
            self._checkEntryMetadata("/etc/passwd-", 0o0644, "root", "root")

        # /etc/group-
        if self._exists("/etc/group-"):
            self._checkFile("/etc/group-")
            self._checkEntryMetadata("/etc/group-", 0o0644, "root", "root")

        # /etc/shadow-
        if self._exists("/etc/shadow-"):
            self._checkFile("/etc/shadow-")
            self._checkEntryMetadata("/etc/shadow-", 0o0640, "root", "root")

        # /etc/gshadow-
        if self._exists("/etc/gshadow-"):
            self._checkFile("/etc/gshadow-")
            self._checkEntryMetadata("/etc/gshadow-", 0o0640, "root", "root")

        # /etc/subuid-
        if self._exists("/etc/subuid-"):
            self._checkFile("/etc/subuid-")
            self._checkEntryMetadata("/etc/subuid-", 0o0644, "root", "root")

        # /etc/subgid-
        if self._exists("/etc/subgid-"):
            self._checkFile("/etc/subgid-")
            self._checkEntryMetadata("/etc/subgid-", 0o0644, "root", "root")

        # /home
        self._checkDir("/home")
        self._checkEntryMetadata("/home", 0o0755, "root", "root")

        # /home/X
        for fn in self._glob("/home/*"):
            self._checkDir(fn)
            self._checkEntryMetadata(fn, 0o0700, os.path.basename(fn), os.path.basename(fn))

        # /lib
        self._checkSymlink("/lib", "usr/lib")

        # /lib64
        self._checkSymlink("/lib64", "usr/lib64")

        # /mnt
        self._checkDir("/mnt")
        self._checkEntryMetadata("/mnt", 0o0755, "root", "root")

        # /opt
        if self._exists("/opt"):
            # /opt
            self._checkDir("/opt")
            self._checkEntryMetadata("/opt", 0o0755, "root", "root")

            # /opt/bin
            if self._exists("/opt/bin"):
                self._checkDir("/opt/bin")
                self._checkEntryMetadata("/opt/bin", 0o0755, "root", "root")

        # /proc
        self._checkDir("/proc")
        self._checkEntryMetadata("/proc", 0o0555, "root", "root")

        # /root
        self._checkDir("/root")
        self._checkEntryMetadata("/root", 0o0700, "root", "root")

        # /run
        self._checkDir("/run")
        self._checkEntryMetadata("/run", 0o0755, "root", "root")

        # /sbin
        self._checkSymlink("/sbin", "usr/sbin")

        # /sys
        self._checkDir("/sys")
        self._checkEntryMetadata("/sys", 0o0555, "root", "root")

        # /tmp
        self._checkDir("/tmp")
        self._checkEntryMetadata("/tmp", 0o1777, "root", "root")

        # /usr
        self._checkDir("/usr")
        self._checkEntryMetadata("/usr", 0o0755, "root", "root")

        # /usr/bin
        self._checkDir("/usr/bin")
        self._checkEntryMetadata("/usr/bin", 0o0755, "root", "root")

        # /usr/games
        if self._exists("/usr/games"):
            # /usr/games
            self._checkDir("/usr/games")
            self._checkEntryMetadata("/usr/games", 0o0755, "root", "root")

            # /usr/games/bin
            if self._exists("/usr/games/bin"):
                self._checkDir("/usr/games/bin")
                self._checkEntryMetadata("/usr/games/bin", 0o0755, "root", "root")

        # /usr/include
        if self._exists("/usr/include"):
            self._checkDir("/usr/include")
            self._checkEntryMetadata("/usr/include", 0o0755, "root", "root")

        # /usr/lib
        self._checkDir("/usr/lib")
        self._checkEntryMetadata("/usr/lib", 0o0755, "root", "root")

        # /usr/lib64
        self._checkDir("/usr/lib64")
        self._checkEntryMetadata("/usr/lib64", 0o0755, "root", "root")

        # /usr/libexec
        self._checkDir("/usr/libexec")
        self._checkEntryMetadata("/usr/libexec", 0o0755, "root", "root")

        # /usr/local
        if self._exists("/usr/local"):
            # /usr/local
            self._checkDir("/usr/local")
            self._checkEntryMetadata("/usr/local", 0o0755, "root", "root")

            # /usr/local/bin
            if self._exists("/usr/local/bin"):
                self._checkDir("/usr/local/bin")
                self._checkEntryMetadata("/usr/local/bin", 0o0755, "root", "root")

            # /usr/local/etc
            if self._exists("/usr/local/etc"):
                self._checkDir("/usr/local/etc")
                self._checkEntryMetadata("/usr/local/etc", 0o0755, "root", "root")

            # /usr/local/games
            if self._exists("/usr/local/games"):
                self._checkDir("/usr/local/games")
                self._checkEntryMetadata("/usr/local/games", 0o0755, "root", "root")

            # /usr/local/include
            if self._exists("/usr/local/include"):
                self._checkDir("/usr/local/include")
                self._checkEntryMetadata("/usr/local/include", 0o0755, "root", "root")

            # /usr/local/lib
            if self._exists("/usr/local/lib"):
                self._checkDir("/usr/local/lib")
                self._checkEntryMetadata("/usr/local/lib", 0o0755, "root", "root")

            # /usr/local/lib64
            if self._exists("/usr/local/lib64"):
                self._checkDir("/usr/local/lib64")
                self._checkEntryMetadata("/usr/local/lib64", 0o0755, "root", "root")

            # /usr/local/man
            if self._exists("/usr/local/man"):
                self._checkDir("/usr/local/man")
                self._checkEntryMetadata("/usr/local/man", 0o0755, "root", "root")

            # /usr/local/sbin
            if self._exists("/usr/local/sbin"):
                self._checkDir("/usr/local/sbin")
                self._checkEntryMetadata("/usr/local/sbin", 0o0755, "root", "root")

            # /usr/local/share
            if self._exists("/usr/local/share"):
                self._checkDir("/usr/local/share")
                self._checkEntryMetadata("/usr/local/share", 0o0755, "root", "root")

            # /usr/local/src
            if self._exists("/usr/local/src"):
                self._checkDir("/usr/local/src")
                self._checkEntryMetadata("/usr/local/src", 0o0755, "root", "root")

        # /usr/sbin
        self._checkDir("/usr/sbin")
        self._checkEntryMetadata("/usr/sbin", 0o0755, "root", "root")

        # /usr/share
        self._checkDir("/usr/share")
        self._checkEntryMetadata("/usr/share", 0o0755, "root", "root")

        # /usr/src
        if self._exists("/usr/src"):
            self._checkDir("/usr/src")
            self._checkEntryMetadata("/usr/src", 0o0755, "root", "root")

        # toolchain directory
        for fn in self._glob("/usr/*"):
            if self._isToolChainName(os.path.basename(fn)):
                self._checkDir(fn)
                self._checkEntryMetadata(fn, 0o0755, "root", "root")

        # /var
        self._checkDir("/var")
        self._checkEntryMetadata("/var", 0o0755, "root", "root")

        # /var/cache
        if self._exists("/var/cache"):
            self._checkDir("/var/cache")
            self._checkEntryMetadata("/var/cache", 0o0755, "root", "root")

        # /var/db
        if self._exists("/var/db"):
            self._checkDir("/var/db")
            self._checkEntryMetadata("/var/db", 0o0755, "root", "root")

        # /var/empty
        if self._exists("/var/empty"):
            self._checkDir("/var/empty")
            self._checkEntryMetadata("/var/empty", 0o0755, "root", "root")

        # /var/games
        if self._exists("/var/games"):
            self._checkDir("/var/games")
            self._checkEntryMetadata("/var/games", 0o0755, "root", "root")

        # /var/lib
        if self._exists("/var/lib"):
            self._checkDir("/var/lib")
            self._checkEntryMetadata("/var/lib", 0o0755, "root", "root")

        # /var/lock
        if self._exists("/var/lock"):
            self._checkSymlink("/var/lock", "../run/lock")

        # /var/log
        if self._exists("/var/log"):
            self._checkDir("/var/log")
            self._checkEntryMetadata("/var/log", 0o0755, "root", "root")

        # /var/run
        if self._exists("/var/run"):
            self._checkSymlink("/var/run", "../run")

        # /var/spool
        if self._exists("/var/spool"):
            self._checkDir("/var/spool")
            self._checkEntryMetadata("/var/spool", 0o0755, "root", "root")

        # /var/swap.dat
        if self._exists("/var/swap.dat"):
            self._checkFile("/var/swap.dat")
            self._checkEntryMetadata("/var/swap.dat", 0o0600, "root", "root")

        # /var/tmp
        self._checkDir("/var/tmp")
        self._checkEntryMetadata("/var/tmp", 0o1777, "root", "root")

        # redundant files
        self._checkNoRedundantEntry("/")
        self._checkNoRedundantEntry("/usr")
        if self._exists("/usr/local"):
            self._checkNoRedundantEntry("/usr/local")
        self._checkNoRedundantEntry("/var")

    def _exists(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        return os.path.exists(fullfn)

    def _glob(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        ret = glob.glob(fullfn)
        ret = ["/" + x[len(self._dirPrefix):] for x in ret]
        return ret

    def _isToolChainName(self, name):
        # FIXME: how to find a complete list?
        if name == "i686-pc-linux-gnu":
            return True
        elif name == "x86_64-pc-linux-gnu":
            return True
        elif name == "x86_64-w64-mingw32":
            return True
        else:
            return False

    def _checkDir(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            if self._bAutoFix:
                os.mkdir(fullfn)
            else:
                raise FshCheckError("\"%s\" does not exist" % (fn))

        if os.path.islink(fullfn) or not os.path.isdir(fullfn):
            # no way to autofix
            raise FshCheckError("\"%s\" is invalid" % (fn))

        self._record.add(fn)

    def _checkFile(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            # no way to autofix
            raise FshCheckError("\"%s\" does not exist" % (fn))

        if os.path.islink(fullfn) or not os.path.isfile(fullfn):
            # no way to autofix
            raise FshCheckError("\"%s\" is invalid" % (fn))

        self._record.add(fn)

    def _checkSymlink(self, fn, target):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            if self._bAutoFix:
                os.symlink(target, fullfn)
            else:
                raise FshCheckError("\"%s\" does not exist" % (fn))

        if not os.path.islink(fullfn):
            if os.path.isdir(fullfn):
                fullTarget = os.path.join(self._dirPrefix, target)
                if os.path.isdir(fullTarget):
                    if self._bAutoFix:
                        ret = filecmp.dircmp(fullfn, fullTarget)
                        if len(ret.common) == 0 and len(ret.common_dirs) == 0:
                            # FIXME
                            raise FshCheckError("\"%s\" is invalid, can autofix" % (fn))
                    else:
                        raise FshCheckError("\"%s\" is invalid" % (fn))
                else:
                    raise FshCheckError("\"%s\" is invalid" % (fn))
            else:
                raise FshCheckError("\"%s\" is invalid" % (fn))
        else:
            if os.readlink(fullfn) != target:
                if self._bAutoFix:
                    os.unlink(fullfn)
                    os.symlink(target, fullfn)
                else:
                    raise FshCheckError("\"%s\" is invalid" % (fn))

        self._record.add(fn)

    def _checkEntryMetadata(self, fn, mode, owner, group):
        assert os.path.isabs(fn)
        assert stat.S_IFMT(mode) == 0                      # no file type bits

        fullfn = os.path.join(self._dirPrefix, fn[1:])
        ownerId = pwd.getpwnam(owner).pw_uid
        groupId = grp.getgrnam(group).gr_gid

        s = os.stat(fullfn)
        if stat.S_IMODE(s.st_mode) != mode:
            if self._bAutoFix:
                os.chmod(fullfn, mode)
            else:
                raise FshCheckError("\"%s\" has invalid permission" % (fn))
            if s.st_uid != ownerId:
                if self._bAutoFix:
                    os.chown(fullfn, ownerId, s.st_gid)
                else:
                    raise FshCheckError("\"%s\" has invalid owner" % (fn))
            if s.st_gid != groupId:
                if self._bAutoFix:
                    os.chown(fullfn, s.st_uid, groupId)
                else:
                    raise FshCheckError("\"%s\" has invalid owner group" % (fn))

        self._record.add(fn)

    def _checkNoRedundantEntry(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self._dirPrefix, fn[1:])

        for fn2 in os.listdir(fullfn):
            fullfn2 = os.path.join(fullfn, fn2)
            if fullfn2 not in self._record:
                raise FshCheckError("\"%s\" should not exist" % (fullfn2[len(self._dirPrefix):]))
