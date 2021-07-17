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


__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


WILDCARDS_LAYOUT = 1             # FSH layout files
WILDCARDS_SYSTEM = 2             # system files
WILDCARDS_SYSTEM_DATA = 3        # system data files
WILDCARDS_SYSTEM_CACHE = 4       # system cache files, subset of system data files
WILDCARDS_USER_DATA = 5          # user data files (including root user)
WILDCARDS_USER_CACHE = 6         # user cache files, subset of user data files
WILDCARDS_USER_TRASH = 7         # trash files, subset of user data files
WILDCARDS_BOOT = 8               # boot files, subset of system files
WILDCARDS_RUNTIME = 9            # runtime files


def merge_wildcards(wildcards1, wildcards2):
    assert all(_HelperWildcard.is_pattern_inc_or_exc(w) for w in wildcards1)        # FIXME
    return wildcards1 + wildcards2


def deduct_wildcards(wildcards1, wildcards2):
    assert all(_HelperWildcard.is_pattern_inc_or_exc(w) for w in wildcards2)        # FIXME
    ret = []
    for w in wildcards2:
        ret.append("- " + w[2:])
    return ret + wildcards1


def wildcards_match(name, wildcards):
    """
    Test whether NAME matches WILDCARDS.

    Wildcard specification:
    o      '+ ' prefix means inclusion, '- ' prefix means exclusion, wildcards are order sensitive.
    o      use '**' to match anything, including slashes, but only trailing "dir_name/**" is allowed.
    o      a trailing "dir_name/***" will match both the directory (as if "dir_name/" had been specified) and everything in the directory (as if "dir_name/**" had been specified).
    o      wildcard must begin with a '/'.
    o      wildcards are case sensitive.
    """

    _HelperWildcard.check_patterns(wildcards)

    for w in wildcards:
        if _HelperWildcard.match_pattern(name, w):
            return _HelperWildcard.is_pattern_inc_or_exc(w)
    return False


def wildcards_filter(names, wildcards):
    """Return the subset of the list NAMES that match WILDCARDS."""

    _HelperWildcard.check_patterns(wildcards)

    result = []
    for name in names:
        for w in wildcards:
            if _HelperWildcard.match_pattern(name, w):
                if _HelperWildcard.is_pattern_inc_or_exc(w):
                    result.append(name)
                else:
                    break
    return result


class RootFs:

    """
    We comply with FHS (https://refspecs.linuxfoundation.org/fhs.shtml) but have some extra rules:
      * Fedora UsrMerge (https://fedoraproject.org/wiki/Features/UsrMove)
      * FreeDesktop Trash Specification (https://freedesktop.org/wiki/Specifications/trash-spec)
      * /etc/hostname for hostname configuration
      * optional toolchain directories in /usr
      * optional swap file /var/swap.dat
    """

    def __init__(self, dirPrefix="/"):
        self._helper = _HelperPrefixedDirOp(self)
        self._dirPrefix = dirPrefix

    def get_wildcards(self, user=None, wildcards_flag=None):
        if wildcards_flag == WILDCARDS_LAYOUT:
            assert user is None
            return self._getWildcardsLayout()
        if wildcards_flag == WILDCARDS_SYSTEM:
            assert user is None
            return self._getWildcardsSystem()
        if wildcards_flag == WILDCARDS_SYSTEM_DATA:
            assert user is None
            return self._getWildcardsSystemData()
        if wildcards_flag == WILDCARDS_SYSTEM_CACHE:
            assert user is None
            return self._getWildcardsSystemCache()
        if wildcards_flag == WILDCARDS_USER_DATA:
            return self._getWildcardsUserData(user)
        if wildcards_flag == WILDCARDS_USER_CACHE:
            return self._getWildcardsUserCache(user)
        if wildcards_flag == WILDCARDS_USER_TRASH:
            return self._getWildcardsUserTrash(user)
        if wildcards_flag == WILDCARDS_BOOT:
            assert user is None
            return self._getWildcardsBoot()
        if wildcards_flag == WILDCARDS_RUNTIME:
            assert user is None
            return self._getWildcardsRuntime()
        assert False

    def wildcards_glob(self, wildcards):
        _HelperWildcard.check_patterns(wildcards)
        return self._wildcardsGlob(wildcards)

    def check(self, deep_check=False, auto_fix=False):
        self._bAutoFix = auto_fix
        self._checkResult = []
        self._record = set()
        try:
            self._check()
            wildcards = self._getWildcardsSystem()
            if deep_check:
                wildcards = merge_wildcards(wildcards, self._getWildcardsSystemData())
            self._deepCheckSystem(self._wildcardsGlob(wildcards))
        finally:
            del self._record
            del self._bAutoFix

    def check_complete(self, raise_exception=False):
        try:
            if not raise_exception:
                return self._checkResult
            else:
                raise CheckError(self._checkResult)
        finally:
            del self._checkResult

    def _check(self):
        # /
        self._checkDir("/", 0o0755, "root", "root")

        # /bin
        self._checkUsrMergeSymlink("/bin", "usr/bin")

        # /boot
        self._checkDir("/boot", 0o0755, "root", "root")

        # /dev
        self._checkDir("/dev", 0o0755, "root", "root")

        # /etc
        self._checkDir("/etc", 0o0755, "root", "root")

        # /etc/hostname
        self._checkFile("/etc/hostname",  0o0644, "root", "root")

        # shadow files in /etc
        # FIXME: in fact they are not basic layout
        self._checkFile("/etc/passwd",  0o0644, "root", "root")
        self._checkFile("/etc/group",   0o0644, "root", "root")
        self._checkFile("/etc/shadow",  0o0640, "root", "root")
        self._checkFile("/etc/gshadow", 0o0640, "root", "root")
        self._checkFile("/etc/subuid",  0o0644, "root", "root")
        self._checkFile("/etc/subgid",  0o0644, "root", "root")
        if self._exists("/etc/passwd-"):
            self._checkFile("/etc/passwd-",  0o0644, "root", "root")
        if self._exists("/etc/group-"):
            self._checkFile("/etc/group-",   0o0644, "root", "root")
        if self._exists("/etc/shadow-"):
            self._checkFile("/etc/shadow-",  0o0640, "root", "root")
        if self._exists("/etc/gshadow-"):
            self._checkFile("/etc/gshadow-", 0o0640, "root", "root")
        if self._exists("/etc/subuid-"):
            self._checkFile("/etc/subuid-",  0o0644, "root", "root")
        if self._exists("/etc/subgid-"):
            self._checkFile("/etc/subgid-",  0o0644, "root", "root")

        # /home
        self._checkDir("/home", 0o0755, "root", "root")
        for fn in self._glob("/home/*"):
            self._checkDir(fn, 0o0700, os.path.basename(fn), os.path.basename(fn))

        # /lib
        self._checkUsrMergeSymlink("/lib", "usr/lib")

        # /lib64
        self._checkUsrMergeSymlink("/lib64", "usr/lib64")

        # /mnt
        self._checkDir("/mnt", 0o0755, "root", "root")

        # /opt
        self._checkDir("/opt", 0o0755, "root", "root")

        # /proc
        self._checkDir("/proc", 0o0555, "root", "root")

        # /root
        self._checkDir("/root", 0o0700, "root", "root")

        # /run
        self._checkDir("/run", 0o0755, "root", "root")

        # /sbin
        self._checkUsrMergeSymlink("/sbin", "usr/sbin")

        # /sys
        self._checkDir("/sys", 0o0555, "root", "root")

        # /tmp
        self._checkDir("/tmp", 0o1777, "root", "root")      # /tmp has stick bit

        # /usr
        self._checkDir("/usr", 0o0755, "root", "root")

        # /usr/bin
        self._checkDir("/usr/bin", 0o0755, "root", "root")

        # /usr/games
        if self._exists("/usr/games"):
            self._checkDir("/usr/games", 0o0755, "root", "root")
            if self._exists("/usr/games/bin"):
                self._checkDir("/usr/games/bin", 0o0755, "root", "root")

        # /usr/include
        if self._exists("/usr/include"):
            self._checkDir("/usr/include", 0o0755, "root", "root")

        # /usr/lib
        self._checkDir("/usr/lib", 0o0755, "root", "root")

        # /usr/lib64
        self._checkDir("/usr/lib64", 0o0755, "root", "root")

        # /usr/libexec
        self._checkDir("/usr/libexec", 0o0755, "root", "root")

        # /usr/local
        if self._exists("/usr/local"):
            self._checkDir("/usr/local", 0o0755, "root", "root")
            if self._exists("/usr/local/bin"):
                self._checkDir("/usr/local/bin", 0o0755, "root", "root")
            if self._exists("/usr/local/etc"):
                self._checkDir("/usr/local/etc", 0o0755, "root", "root")
            if self._exists("/usr/local/games"):
                self._checkDir("/usr/local/games", 0o0755, "root", "root")
            if self._exists("/usr/local/include"):
                self._checkDir("/usr/local/include", 0o0755, "root", "root")
            if self._exists("/usr/local/lib"):
                self._checkDir("/usr/local/lib", 0o0755, "root", "root")
            if self._exists("/usr/local/lib64"):
                self._checkDir("/usr/local/lib64", 0o0755, "root", "root")
            if self._exists("/usr/local/man"):
                self._checkDir("/usr/local/man", 0o0755, "root", "root")
            if self._exists("/usr/local/sbin"):
                self._checkDir("/usr/local/sbin", 0o0755, "root", "root")
            if self._exists("/usr/local/share"):
                self._checkDir("/usr/local/share", 0o0755, "root", "root")
            if self._exists("/usr/local/src"):
                self._checkDir("/usr/local/src", 0o0755, "root", "root")

        # /usr/sbin
        self._checkDir("/usr/sbin", 0o0755, "root", "root")

        # /usr/share
        self._checkDir("/usr/share", 0o0755, "root", "root")

        # /usr/src
        if self._exists("/usr/src"):
            self._checkDir("/usr/src", 0o0755, "root", "root")

        # toolchain directories in /usr
        for fn in self._glob("/usr/*"):
            if _isToolChainName(os.path.basename(fn)):
                self._checkDir(fn, 0o0755, "root", "root")

        # /var
        self._checkDir("/var", 0o0755, "root", "root")

        # /var/cache
        if self._exists("/var/cache"):
            self._checkDir("/var/cache", 0o0755, "root", "root")

        # /var/db
        if self._exists("/var/db"):
            self._checkDir("/var/db", 0o0755, "root", "root")

        # /var/empty (home directory for user "nobody")
        self._checkDir("/var/empty", 0o0755, "root", "root")
        self._checkDirIsEmpty("/var/empty")

        # /var/games
        if self._exists("/var/games"):
            self._checkDir("/var/games", 0o0755, "root", "root")

        # /var/lib
        if self._exists("/var/lib"):
            self._checkDir("/var/lib", 0o0755, "root", "root")

        # /var/lock
        self._checkSymlink("/var/lock", "../run/lock")

        # /var/log
        if self._exists("/var/log"):
            self._checkDir("/var/log", 0o0755, "root", "root")

        # /var/run
        self._checkSymlink("/var/run", "../run")

        # /var/spool
        if self._exists("/var/spool"):
            self._checkDir("/var/spool", 0o0755, "root", "root")

        # /var/swap.dat
        if self._exists("/var/swap.dat"):
            self._checkFile("/var/swap.dat", 0o0600, "root", "root")

        # /var/tmp
        self._checkDir("/var/tmp", 0o1777, "root", "root")      # /var/tmp has stick bit

        # /var/www
        if self._exists("/var/www"):
            self._checkDir("/var/www", 0o0775, "root", "root")

        # redundant files
        self._checkNoRedundantEntry("/")
        self._checkNoRedundantEntry("/usr")
        if self._exists("/usr/local"):
            self._checkNoRedundantEntry("/usr/local")
        self._checkNoRedundantEntry("/var")

    def _deepCheckSystem(self, fnList):
        for fn in fnList:
            fullfn = os.path.join(self._dirPrefix, fn[1:])
            if not os.path.exists(fullfn):
                if os.path.islink(fullfn):
                    self._checkResult.append("\"%s\" is a broken symlink." % (fn))
                else:
                    self._checkResult.append("\"%s\" does not exist?!" % (fn))
            else:
                st = os.stat(fullfn)
                if True:
                    try:
                        pwd.getpwuid(st.st_uid)
                    except KeyError:
                        self._checkResult.append("\"%s\" has an invalid owner." % (fn))
                    try:
                        grp.getgrgid(st.st_gid)
                    except KeyError:
                        self._checkResult.append("\"%s\" has an invalid group." % (fn))
                if True:
                    if not (st.st_mode & stat.S_IRUSR):
                        self._checkResult.append("\"%s\" is not readable by owner." % (fn))
                    if not (st.st_mode & stat.S_IWUSR):
                        # FIXME: there're so many files violates this rule, strange
                        # self._checkResult.append("\"%s\" is not writeable by owner." % (fn))
                        pass
                    if not (st.st_mode & stat.S_IRGRP) and (st.st_mode & stat.S_IWGRP):
                        self._checkResult.append("\"%s\" is not readable but writable by group." % (fn))
                    if not (st.st_mode & stat.S_IROTH) and (st.st_mode & stat.S_IWOTH):
                        self._checkResult.append("\"%s\" is not readable but writable by other." % (fn))
                    if not (st.st_mode & stat.S_IRGRP) and ((st.st_mode & stat.S_IROTH) or (st.st_mode & stat.S_IWOTH)):
                        self._checkResult.append("\"%s\" is not readable by group but readable/writable by other." % (fn))
                    if not (st.st_mode & stat.S_IWGRP) and (st.st_mode & stat.S_IWOTH):
                        self._checkResult.append("\"%s\" is not writable by group but writable by other." % (fn))
                if os.path.isdir(fullfn) and not os.path.islink(fullfn):
                    if (st.st_mode & stat.S_ISUID):
                        self._checkResult.append("\"%s\" should not have SUID bit set." % (fn))
                    if (st.st_mode & stat.S_ISGID):
                        # if showdn.startswith("/var/lib/portage"):
                        #     pass        # FIXME, portage set SGID for these directories?
                        # elif showdn.startswith("/var/log/portage"):
                        #     pass        # FIXME, portage set SGID for these directories?
                        # elif showdn.startswith("/var/log/journal"):
                        #     pass        # FIXME, systemd set SGID for these directories?
                        # else:
                        #     self._checkResult.append("\"%s\" should not have SGID bit set." % (showdn))
                        pass
                else:
                    if (st.st_mode & stat.S_ISUID):
                        bad = False
                        if not (st.st_mode & stat.S_IXUSR):
                            bad = True
                        if not (st.st_mode & stat.S_IXGRP) and ((st.st_mode & stat.S_IRGRP) or (st.st_mode & stat.S_IWGRP)):
                            bad = True
                        if not (st.st_mode & stat.S_IXOTH) and ((st.st_mode & stat.S_IROTH) or (st.st_mode & stat.S_IWOTH)):
                            bad = True
                        if bad:
                            self._checkResult.append("\"%s\" is not appropriate for SUID bit." % (fn))
                    if (st.st_mode & stat.S_ISGID):
                        # FIXME
                        # self.infoPrinter.printError("File \"%s\" should not have SGID bit set." % (showfn))
                        pass
                if (st.st_mode & stat.S_ISVTX):
                    self._checkResult.append("\"%s\" should not have sticky bit set." % (fn))

    def _getWildcardsLayout(self):
        ret = [
            "+ /",
            "+ /bin",             # symlink
            "+ /boot",
            "+ /dev",
            "+ /etc",
            "+ /etc/hostname",
            "+ /home",
            "+ /lib",             # symlink
            "+ /lib64",           # symlink
            "+ /mnt",
            "+ /opt",
            "+ /proc",
            "+ /root",
            "+ /run",
            "+ /sbin",            # symlink
            "+ /sys",
            "+ /tmp",
            "+ /usr",
            "+ /usr/bin",
        ]
        if self._exists("/usr/games"):
            ret.append("+ /usr/games")
            if self._exists("/usr/games/bin"):
                ret.append("+ /usr/games/bin")
        if self._exists("/usr/include"):
            ret.append("+ /usr/include")
        ret += [
            "+ /usr/lib",
            "+ /usr/lib64",
            "+ /usr/libexec",
        ]
        if self._exists("/usr/local"):
            ret.append("+ /usr/local")
            if self._exists("/usr/local/bin"):
                ret.append("+ /usr/local/bin")
            if self._exists("/usr/local/etc"):
                ret.append("+ /usr/local/etc")
            if self._exists("/usr/local/games"):
                ret.append("+ /usr/local/games")
            if self._exists("/usr/local/include"):
                ret.append("+ /usr/local/include")
            if self._exists("/usr/local/lib"):
                ret.append("+ /usr/local/lib")
            if self._exists("/usr/local/lib64"):
                ret.append("+ /usr/local/lib64")
            if self._exists("/usr/local/man"):
                ret.append("+ /usr/local/man")
            if self._exists("/usr/local/sbin"):
                ret.append("+ /usr/local/sbin")
            if self._exists("/usr/local/share"):
                ret.append("+ /usr/local/share")
        if True:
            ret.append("+ /usr/opt")
            if self._exists("/usr/opt/bin"):
                ret.append("+ /usr/opt/bin")
        ret += [
            "+ /usr/sbin",
            "+ /usr/share",
        ]
        for fn in self._glob("/usr/*"):
            if _isToolChainName(os.path.basename(fn)):
                ret.append("+ %s" % (fn))
        ret += [
            "+ /var",
        ]
        if self._exists("/var/cache"):
            ret.append("+ /var/cache")
        if self._exists("/var/db"):
            ret.append("+ /var/db")
        ret += [
            "+ /var/empty",       # empty directory
        ]
        if self._exists("/var/lib"):
            ret.append("+ /var/lib")
        ret += [
            "+ /var/lock",        # symlink
        ]
        if self._exists("/var/log"):
            ret.append("+ /var/log")
        ret += [
            "+ /var/run",         # symlink
            "+ /var/tmp",
        ]
        return ret

    def _getWildcardsSystem(self):
        return [
            "+ /boot/**",
            "+ /etc/**",
            "+ /usr/**",
        ]

    def _getWildcardsSystemData(self):
        ret = []
        if self._exists("/var/cache"):
            ret.append("+ /var/cache/**")
        if self._exists("/var/db"):
            ret.append("+ /var/db/**")
        if self._exists("/var/lib"):
            ret.append("+ /var/lib/**")
        if self._exists("/var/log"):
            ret.append("+ /var/log/**")
        if self._exists("/var/swap.dat"):
            ret.append("+ /var/swap.dat")
        return ret

    def _getWildcardsSystemCache(self):
        ret = []
        if self._exists("/var/cache"):
            ret.append("+ /var/cache/**")
        return ret

    def _getWildcardsUserData(self, user):
        ret = []
        if user is None or user == "root":
            ret.append("+ /root/**")                # "/root" belongs to FSH layout
        for fn in self._glob("/home/*"):
            if user is None or user == os.path.basename(fn):
                ret.append("+ %s/***" % (fn))       # "/home/X" belongs to user data
        assert len(ret) > 0
        return ret

    def _getWildcardsUserCache(self, user):
        ret = []
        if user is None or user == "root":
            if self._exists("/root/.cache"):
                ret.append("+ /root/.cache/**")
        for fn in self._glob("/home/*"):
            if user is None or user == os.path.basename(fn):
                if self._exists("%s/.cache" % (fn)):
                    ret.append("+ %s/.cache/**" % (fn))
        assert len(ret) > 0
        return ret

    def _getWildcardsUserTrash(self, user):
        ret = []
        if user is None or user == "root":
            if self._exists("/root/.local/share/Trash"):
                ret.append("+ /root/.local/share/Trash/**")
        for fn in self._glob("/home/*"):
            if user is None or user == os.path.basename(fn):
                if self._exists("%s/.local/share/Trash" % (fn)):
                    ret.append("+ %s/.local/share/Trash/**" % (fn))
        assert len(ret) > 0
        return ret

    def _getWildcardsBoot(self):
        return [
            "+ /boot/**",
            "+ /usr/lib/modules/***",
            "+ /usr/lib/firmware/***",
        ]

    def _getWildcardsRuntime(self):
        ret = [
            "+ /dev/**",
            "+ /mnt/**",
            "+ /proc/**",
            "+ /run/**",
            "+ /sys/**",
            "+ /tmp/**",
        ]
        if self._exists("/var/spool"):
            ret.append("+ /var/spool/**")
        ret += [
            "+ /var/tmp/**",
        ]
        return ret

    def _wildcardsGlob(self, wildcards):
        wildcards2 = []
        for w in wildcards:
            w2 = w[:2] + os.path.join(self._dirPrefix, w[3:])
            wildcards2.append(w2)

        ret = []
        self._wildcardsGlobImpl(self._dirPrefix, wildcards2, ret)
        ret = ["/" + x[len(self._dirPrefix):] for x in ret]
        return ret

    def _wildcardsGlobImpl(self, curPath, wildcards, result):
        if os.path.isdir(curPath) and not os.path.islink(curPath):
            bRecorded = False
            bRecursive = False
            for w in wildcards:
                if _HelperWildcard.match_pattern(curPath, w):
                    if _HelperWildcard.is_pattern_inc_or_exc(w):
                        if not bRecorded:
                            result.append(curPath)
                            bRecorded = True
                        if w.endswith("/***") or w.endswith("/**"):
                            bRecursive = True
                            break
                    else:
                        bRecorded = True
                        if w.endswith("/***") or w.endswith("/**"):
                            break
                else:
                    if _HelperWildcard.is_pattern_inc_or_exc(w) and w[2:].startswith(_pathAddSlash(curPath)):
                        bRecursive = True
                        if bRecorded:
                            break
            if bRecursive:
                for fn in os.listdir(curPath):
                    self._wildcardsGlobImpl(os.path.join(curPath, fn), wildcards, result)
        else:
            for w in wildcards:
                if _HelperWildcard.match_pattern(curPath, w):
                    if _HelperWildcard.is_pattern_inc_or_exc(w):
                        result.append(curPath)
                    return

    def __getattr__(self, attr):
        return getattr(self._helper, attr)


class PreMountRootFs:

    def __init__(self, dir, mounted_boot=True, mounted_home=True, mounted_usr=True, mounted_var=True):
        self._helper = _HelperPrefixedDirOp(self)
        self._dirPrefix = dir
        self._bMountBoot = mounted_boot     # /boot is mounted
        self._bMountHome = mounted_home     # /root, /home are mounted
        self._bMountUsr = mounted_usr       # /etc, /opt, /usr is mounted
        self._bMountVar = mounted_var       # /var is mounted

    def check(self, auto_fix=False):
        self._bAutoFix = auto_fix
        self._checkResult = []
        self._record = set()
        try:
            # /bin
            self._checkUsrMergeSymlink("/bin", "usr/bin")

            # /boot
            self._checkDir("/boot")
            if self._bMountBoot:
                self._checkDirIsEmpty("/boot")

            # /dev
            self._checkDir("/dev")
            self._checkDevNode("/dev/console", 5, 1, 0o0600, "root", "root")
            self._checkDevNode("/dev/null",    1, 3, 0o0666, "root", "root")

            # /etc
            self._checkDir("/etc")
            if self._bMountUsr:
                self._checkDirIsEmpty("/etc")

            # /home
            self._checkDir("/home")
            if self._bMountHome:
                self._checkDirIsEmpty("/home")

            # /lib
            self._checkUsrMergeSymlink("/lib", "usr/lib")

            # /lib64
            self._checkUsrMergeSymlink("/lib64", "usr/lib64")

            # /mnt
            self._checkDir("/mnt")
            self._checkDirIsEmpty("/mnt")

            # /opt
            self._checkDir("/opt")
            if self._bMountUsr:
                self._checkDirIsEmpty("/opt")

            # /proc
            self._checkDir("/proc")
            self._checkDirIsEmpty("/proc")

            # /root
            self._checkDir("/root")
            if self._bMountHome:
                self._checkDirIsEmpty("/root")

            # /run
            self._checkDir("/run")
            self._checkDirIsEmpty("/run")

            # /sbin
            self._checkUsrMergeSymlink("/sbin", "usr/sbin")

            # /sys
            self._checkDir("/sys")
            self._checkDirIsEmpty("/sys")

            # /tmp
            self._checkDir("/tmp")
            self._checkDirIsEmpty("/tmp")

            # /usr
            self._checkDir("/usr")
            if self._bMountUsr:
                self._checkDirIsEmpty("/usr")

            # /var
            self._checkDir("/var")
            if self._bMountVar:
                self._checkDirIsEmpty("/var")

            # redundant files
            self._checkNoRedundantEntry("/")
            self._checkNoRedundantEntry("/dev", True)
        finally:
            del self._record
            del self._bAutoFix

    def check_complete(self, raise_exception=False):
        try:
            if not raise_exception:
                return self._checkResult
            else:
                raise CheckError(self._checkResult)
        finally:
            del self._checkResult

    def __getattr__(self, attr):
        return getattr(self._helper, attr)


class CheckError(Exception):
    pass


class WildcardError(Exception):
    pass


class MoveDirError(Exception):
    pass


class _HelperWildcard:

    @staticmethod
    def check_patterns(wildcards):
        for w in wildcards:
            if not w.startswith("+ ") and not w.startswith("- "):
                raise WildcardError("invalid wildcard \"%s\"" % (w))
            if len(w) < 3 or w[2] != '/':
                raise WildcardError("invalid wildcard \"%s\"" % (w))
            if "*" in w and not w.endswith("/***") and not w.endswith("/**"):
                raise WildcardError("invalid wildcard \"%s\"" % (w))

    @staticmethod
    def match_pattern(name, wildcard):
        p = wildcard[2:]
        if p.endswith("/***"):
            p = os.path.dirname(p)
            if name == p or name.startswith(_pathAddSlash(p)):
                return True
        elif p.endswith("/**"):
            p = os.path.dirname(p)
            if name.startswith(_pathAddSlash(p)):
                return True
        else:
            if name == p:
                return True
        return False

    @staticmethod
    def is_pattern_inc_or_exc(wildcard):
        return wildcard.startswith("+ ")


class _HelperPrefixedDirOp:

    # we need self.p._dirPrefix, self.p._bAutoFix, self.p._record, self.p._checkResult

    def __init__(self, parent):
        self.p = parent

    def _exists(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        return os.path.exists(fullfn)

    def _glob(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        ret = glob.glob(fullfn)
        ret = ["/" + x[len(self.p._dirPrefix):] for x in ret]
        return ret

    def _checkDir(self, fn, mode=None, owner=None, group=None):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            if self.p._bAutoFix:
                os.mkdir(fullfn)
            else:
                self.p._checkResult.append("\"%s\" does not exist." % (fn))
                return

        if os.path.islink(fullfn) or not os.path.isdir(fullfn):
            # no way to autofix
            self.p._checkResult.append("\"%s\" is invalid." % (fn))
            return

        if mode is not None:
            self.__checkMetadata(fn, fullfn, mode, owner, group)

        self.p._record.add(fn)

    def _checkFile(self, fn, mode=None, owner=None, group=None):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            # no way to autofix
            self.p._checkResult.append("\"%s\" does not exist." % (fn))
            return

        if os.path.islink(fullfn) or not os.path.isfile(fullfn):
            # no way to autofix
            self.p._checkResult.append("\"%s\" is invalid." % (fn))
            return

        if mode is not None:
            self.__checkMetadata(fn, fullfn, mode, owner, group)

        self.p._record.add(fn)

    def _checkSymlink(self, fn, target):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            if self.p._bAutoFix:
                os.symlink(target, fullfn)
            else:
                self.p._checkResult.append("\"%s\" does not exist." % (fn))
                return

        if not os.path.islink(fullfn):
            # no way to autofix
            self.p._checkResult.append("\"%s\" is invalid." % (fn))
            return

        if os.readlink(fullfn) != target:
            if self.p._bAutoFix:
                os.unlink(fullfn)
                os.symlink(target, fullfn)
            else:
                self.p._checkResult.append("\"%s\" is invalid." % (fn))
                return

        self.p._record.add(fn)

    def _checkUsrMergeSymlink(self, fn, target):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])
        fullTarget = os.paht.join(os.path.dirname(fullfn), target)

        if not _isRealDir(fullTarget):
            # no way to autofix
            self.p._checkResult.append("\"%s\" is invalid." % (fullTarget))
            return

        if not os.path.exists(fullfn):
            if self.p._bAutoFix:
                os.symlink(target, fullfn)
            else:
                self.p._checkResult.append("\"%s\" does not exist." % (fn))
                return

        if not os.path.islink(fullfn):
            if _isRealDir(fullfn):
                ret = _HelperMoveDir.compare_dir(fullfn, fullTarget)
                if len(ret) == 0:
                    _HelperMoveDir.move_dir(fullfn, fullTarget)
                    os.rmdir(fullfn)
                    os.symlink(target, fullfn)
                else:
                    self.p._checkResult.append("Directory \"%s\" and \"%s\" has common files, no way to combine them." % (fn, target))
                    return
            else:
                # no way to autofix
                self.p._checkResult.append("\"%s\" is invalid." % (fullTarget))
                return

        if os.readlink(fullfn) != target:
            if self.p._bAutoFix:
                os.unlink(fullfn)
                os.symlink(target, fullfn)
            else:
                self.p._checkResult.append("\"%s\" is invalid." % (fn))
                return

        self.p._record.add(fn)

    def _checkDevNode(self, fn, major, minor, mode=None, owner=None, group=None):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])

        if not os.path.exists(fullfn):
            # FIXME: autofix
            self.p._checkResult.append("\"%s\" does not exist." % (fn))
            return

        # FIXME: check major, minor

        if mode is not None:
            self.__checkMetadata(fn, fullfn, mode, owner, group)

        self.p._record.add(fn)

    def _checkDirIsEmpty(self, fn):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])
        bFound = False
        for fn2 in os.listdir(fullfn):
            if not fn2.startswith(".keep"):
                bFound = True
                break
        if bFound:
            # dangerous to autofix
            self.p._checkResult.append("\"%s\" is not empty." % (fn))

    def _checkMetadata(self, fn, mode, owner, group):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])
        self.__checkMetadata(fn, fullfn, mode, owner, group)

    def _checkNoRedundantEntry(self, fn, bIgnoreDotKeepFiles=False):
        assert os.path.isabs(fn)
        fullfn = os.path.join(self.p._dirPrefix, fn[1:])
        for fn2 in os.listdir(fullfn):
            if bIgnoreDotKeepFiles and fn2.startswith(".keep"):
                continue
            fullfn2 = os.path.join(fn, fn2)
            if fullfn2 not in self.p._record:
                self.p._checkResult.append("\"%s\" should not exist." % (fullfn2))

    def __checkMetadata(self, fn, fullfn, mode, owner, group):
        assert stat.S_IFMT(mode) == 0                      # no file type bits

        s = os.stat(fullfn)
        ownerId = pwd.getpwnam(owner).pw_uid
        groupId = grp.getgrnam(group).gr_gid
        if stat.S_IMODE(s.st_mode) != mode:
            if self.p._bAutoFix:
                os.chmod(fullfn, mode)
            else:
                self.p._checkResult.append("\"%s\" has invalid permission." % (fn))
            if s.st_uid != ownerId:
                if self.p._bAutoFix:
                    os.chown(fullfn, ownerId, s.st_gid)
                else:
                    self.p._checkResult.append("\"%s\" has invalid owner." % (fn))
            if s.st_gid != groupId:
                if self.p._bAutoFix:
                    os.chown(fullfn, s.st_uid, groupId)
                else:
                    self.p._checkResult.append("\"%s\" has invalid owner group." % (fn))


class _HelperMoveDir:

    @staticmethod
    def compare_dir(src, dst):
        left_list = os.listdir(src)
        right_list = os.listdir(dst)
        ret = []

        for li in left_list:
            if li not in right_list:
                continue

            fli = os.path.join(src, li)
            fri = os.path.join(dst, li)

            r1 = (os.path.islink(fli) and os.path.realpath(fli) == os.path.abspath(fri))
            r2 = (os.path.islink(fri) and os.path.realpath(fri) == os.path.abspath(fli))
            if r1 or r2:
                continue

            if not _isRealDir(fli):
                ret.append((fli, "left-file"))
                continue

            if not _isRealDir(fri):
                ret.append((fli, "right-file"))
                continue

            if not _hasSameStat(fli, fri):
                ret.append((fli, "stat-not-same"))
                continue

            ret += _HelperMoveDir.compare_dir(fli, fri)

        return ret

    @staticmethod
    def move_dir(src, dst):
        left_list = os.listdir(src)
        right_list = os.listdir(dst)

        for li in left_list:
            fli = os.path.join(src, li)
            fri = os.path.join(dst, li)

            if li not in right_list:
                os.rename(fli, fri)
                continue

            if os.path.islink(fli) and os.path.realpath(fli) == os.path.abspath(fri):
                os.remove(fli)
                continue

            if os.path.islink(fri) and os.path.realpath(fri) == os.path.abspath(fli):
                os.remove(fri)
                os.rename(fli, fri)
                continue

            if _isRealDir(fli) and _isRealDir(fri) and _hasSameStat(fli, fri):
                _HelperMoveDir.move_dir(fli, fri)
            else:
                raise MoveDirError(fli)

        os.rmdir(src)


def _isToolChainName(name):
    # FIXME: how to find a complete list?
    if name == "i686-pc-linux-gnu":
        return True
    elif name == "x86_64-pc-linux-gnu":
        return True
    elif name == "x86_64-w64-mingw32":
        return True
    else:
        return False


def _pathAddSlash(path):
    if path == "/":
        return path
    else:
        return path + "/"


def _isRealDir(path):
    return os.path.isdir(path) and not os.path.islink(path)


def _hasSameStat(path1, path2):
    st1 = os.stat(path1)
    st2 = os.stat(path2)
    if st1.st_mode != st2.st_mode:
        return False
    if st1.st_uid != st2.st_uid:
        return False
    if st1.st_gid != st2.st_gid:
        return False
    return True
