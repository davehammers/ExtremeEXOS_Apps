# ******************************************************
#
#  Copyright (c) Extreme Networks Inc. 2019
#  All rights reserved
#
# ******************************************************
'''
clone is an EXOS application that clones the:
    /alt/boot
    /alt/exos
    /alt/root
    /boot
    /exos
    /root
    /config
directorys from a remote system to the local one.

In the remainder of this description, a switch can take on 2 distinct roles:
    master - the switch that has the desired EXOS partitions and desired configurations
    client - the switch that will be updated with the master switch information

There are a number of cloning scenarios.

Standalone to Standalone
------------------------
In this scenario, the user wants to create an exact copy of a running switch.
This may be a scenario where the user has a 'golden' switch image and configuration,
scripts, policy files etc...

All new switches should begin with the master switch configuration.

On the master:
    run script clone.py master
        - This starts the cloning server on the master switch
        - The cloning server continutes to run until the user enters:
            run script clone.py stop
        - The cloning server will restart after reboot until the 'stop' command is issued

On the client:
    run script clone.py from <ipaddress>
        - A check is made to see if <ipaddress> can be contacted before continuing
        - If necessary, the client will enable DHCP to get an IP address
        - An image of the master switch is transferred to the client
        - The client reboots with the same partitions and configuration file from the master

Standalone to Master Stack
--------------------------
In this scenario, the standalone switch is intended to be connected to an existing stack.
The client switch may be intended to be an addition to the stack, or a replacement one of
the existing stack switches.

On the stack master:
    run script clone.py master
        - this is the same command for all switches serving cloning clients

New Stack Member Client:
***********************
    To let clone.py find the lowest available slot:
        run script clone.py from <ipaddress> -s0
            - the -s <slot> option where the slot number is zero(0) tells the cloning
                application to find the lowest available slot number
            - the client switch will not be automatically enabled for master capable

    To tell the cloning app, the new stack member should have a specific slot number:
        run script clone.py from <ipaddress> -s <slot>
            - <slot> is a number from 1-8
            - if the slot number exists in the stack, see Existing Stack Member Client
            - the client will be cloned from the stack and assigned the <slot> number
                provided
            - the client switch will not be automatically enabled for master capable

Existing Stack Member Client:
*****************************
    To let clone.py copy the stacking parameters of an existing stacking slot:
        run script clone.py from <ipaddress> -s <slot>
            - <slot> is an existing stacking slot
            - If <slot> does not exist in the master stack, see New Stack Member Client
            - The client will have the same stacking capability (master/standby) as the
                existing master stack slot


In stack synchronize:
---------------------
In this scenario, a stack has already been built, but a slot may not have the current image
needed to join the stack, or the partitions do not align with the master switch.

This is equivalent to the EXOS synchronize command:
    On the stack master:
        run script clone.py slot <slot>
            - the clone.py master server will automatically start on the stack master
            - <slot> will copy the partition and /config information from the stack master
            - the slot will reboot when the clone operation is complete
'''
from os import (
    remove as os_remove,
    getenv,
    getpid,
    O_CREAT,
    O_WRONLY,
    O_TRUNC,
    makedirs,
    mkdir,
    chown,
    environ,
    access,
    W_OK,
    getcwd,
    chdir,
    listdir,
    )
from os.path import (
    basename,
    dirname,
    splitext,
    isdir,
    isfile,
    exists,
    )
import sys
from json import (
    loads as json_loads,
    load as json_load,
    dumps as json_dumps,
    dump as json_dump
    )
from subprocess import (
    CalledProcessError as subprocess_CalledProcessError,
    check_call as subprocess_check_call,
    check_output as subprocess_check_output
    )
from socket import (
    socket,
    AF_INET,
    AF_INET6,
    SOCK_STREAM,
    SOL_SOCKET,
    error,
    inet_pton,
    timeout as socket_timeout
    )
from argparse import (
    ArgumentParser as argparse_ArgumentParser
    )
from time import (
    time,
    sleep,
    strftime,
    )
import logging
import threading
import struct
import binascii
from shutil import (
    copyfile,
    rmtree,
    )
import StringIO
from xml.etree.ElementTree import (
    ElementTree
    )
from re import (
    compile as re_compile,
    search as re_search,
    sub as re_sub,
    )
import tarfile as tar


__version__ = '1.2.0.4'

## --------------------------------------------------
#   1.2.0.4
#   xos0076526 - Remove LED locator CLIs in the short term for 30.4 until LED timer issue is fixed in HAL. See CR comment for details.
#   xos0075784 - Clean up process after CloneUsbExpy is stopped.
# --------------------------------------------------
#   1.2.0.3
#   xos0075784 - Handle EXOS version strings with non-numerics.  i.e. 30.2.1.8-patch2-4
# --------------------------------------------------
#   1.2.0.2
#   xos0075504 - X465 failing minimum flash size check.
#   xos0075455 - Fix network filesystem compatability check.
# --------------------------------------------------
#   1.2.0.1
#   xos0075455 - Add support for block-based root filesystems.
#                NOTE WELL: Not compatible with earlier versions of this script.
# --------------------------------------------------
#   1.1.0.19
#   xos0074844 - Fix clone master timout when cloning stack nodes over alternate stacking links
# --------------------------------------------------
#   1.1.0.18
#   xos0071903 - ZTP-USB clone method is not working properly
# --------------------------------------------------
#   1.1.0.17
#   xos0072129 - clone.py slot all throws error like No compatible slots can be found
# --------------------------------------------------
#   1.1.0.16
#   xos0071946 - fdisk -l is not correctly parsed when looking for flash size
# --------------------------------------------------
#   1.1.0.15
#   nobug - EXOS 30.1 remove reference to /proc system for VR translation
# --------------------------------------------------
#   1.1.0.14
#   xos0070353 - Clone App: from X690 stack to standalone disables stacking-support
# --------------------------------------------------
#   1.1.0.13
#   xos0070317 - Clone App: Card mismatch error, if stack replication tried using USB
# --------------------------------------------------
#   1.1.0.12
#              - PEP8
#   xos0070272 - Clone App: run script clone.py slot 1 must be invalid, if slot 1 is stack master
# --------------------------------------------------
#   1.1.0.11
#   xos0070127 - only remount partitions r/w if not already writeable
#   xos0070129 - clone stack members furthest away from master first
#              - stack cloning autoexec output to stderr
# --------------------------------------------------
#   1.1.0.10
#   xos0069993 - Clone App: GRUB loader shows incorrect image (previous loaded image)
#   xos0069988 - Clone App: synchronize slot does not work for standby slots
# --------------------------------------------------
#   1.1.0.9
#               - wrong boot partition cloned
# --------------------------------------------------
#   1.1.0.8
#   xos0069902 - Clone App: Stack replication does not work
# --------------------------------------------------
#   1.1.0.7
#   xos0069525 - remove 'restart' command line option
# --------------------------------------------------
#   1.1.0.6
#   xos0069537 Clone App: clone is incomplete, if executed with --exos_only
#   xos0069561 Clone App: vpex config is not cloned
# --------------------------------------------------
#   1.1.0.5
#   xos0069397 Clone App: ONIE to EXOS or vice-versa do not fail, if cloned using USB
#   xos0069386 Clone App: "clone.py usb -v" does not differentiate ONIE or EXOS version
#   xos0069403 Clone App: clone.py does not connect thru IPv6
# --------------------------------------------------
#   1.1.0.4
#   xos0069257 Clone App: Error message needed if clone initiated from ONIE to EXOS or vice-versa
#
# --------------------------------------------------
#   1.1.0.3
#   xos0069248 Clone App: mem-limit change occurs for the group OTHER
#   xos0069255 Clone App: not releasing memory to OTHER group which stuck in 17% utilization in X670G2 Clone Master
#   xos0069260 Clone App: Restarting the clone app adds/ increase OTHER group memory-limit to "5%"
#
# --------------------------------------------------
#   1.1.0.1
# clone a stack
#   run script clone.py from <ip> - where <ip> is a stack
#   run script clone.py usb -i <file> where <file> is a stack clone image
#
# --------------------------------------------------
#   1.0.0.2
# add clone USB support
# add --install support for both EXOS partitions
#
# --------------------------------------------------
#   1.0.0.1
#
# Initial release
# Compatible with EXOS 15.7 and beyond

# Determine our running context by which import is available
try:
    import exsh
    i_am_script = True
except Exception:
    from exos.api import exec_cli
    i_am_script = False
    try:
        from exos.api.cmbackend import (cmbackend_init, CmAgent)
        from exos.api import ready
        has_cm_backend = True
    except Exception:
        has_cm_backend = False


# **********************************************************************
# C O N S T A N T S
# **********************************************************************
NVRAM_FILE = "/persistent/preserveOnRescue/system.nvram"
if not isfile(NVRAM_FILE):
    NVRAM_FILE = '/dev/exosNvram'

EEPROM_FILE = "/persistent/preserveOnRescue/system.eeprom"
if not isfile(EEPROM_FILE):
    EEPROM_FILE = '/dev/s450/prommb'

CLONE_STK_SLOTS_FILE = '/usr/local/tmp/cloneslots.json'
# this is the data structure for the file
SLOTLIST = 'slotlist'
clone_slots_dict = {
        SLOTLIST: None
        }


class XosDB(object):
    PROCESS_NAME = splitext(basename(__file__))[0]
    PROCESS_NAME_PY = PROCESS_NAME + '.py'
    SOCKET_PORT = 61111
    MASTER_SOCKET_TIMEOUT = None
    CLIENT_SOCKET_TIMEOUT = None
    ROOT = '/'
    ALT_ROOT = '/alt/'
    TAR = 'tar'
    CAT = 'cat'
    CLI = 'cli'
    SHELL = 'shell'
    CPIO = 'cpio'

    LOGIN = 'admin'

    USB_DIR = '/usr/local/ext/'
    USB_FILENAME = USB_DIR + 'xos{serno}_{t}.cln'
    USB_ROOT_DICT = '/scratch/root_fs_dictionary'
    USB_MASTER_VERSION = '/scratch/clone_version'
    ROOT_ARCHIVE = '/scratch/.clone_{hash}'
    TMP_DIR = '/tmp'
    VER1 = 'exos/bin/spec'
    VER2 = 'alt/exos/bin/spec'
    TMP_NVRAM_FILE = 'scratch/exosNvram'
    STAGED_ROOT = '/etc/extreme/.clone_root__'
    CMP_GREATER_THAN = '>'
    CMP_LESSER_THAN = '<'
    CMP_EQUAL = '='

    # master
    class RequestParams:
        ROOT = 'root'
        DIRS = 'dirs'
        EXCLUDE = 'exclude'
        DM_SYSTEM = 'dmSystem'
        ARCHIVE = 'archive'
    RQST = RequestParams()

    class Epm(object):
        MODULE = 'epm'

        class Epmpcb(object):
            BLOCK = 'epmpcb'

            DATA = 'data'
            NAME = 'name'
            PID = 'pid'
        PCB = Epmpcb()

        class Epmpcg(object):
            BLOCK = 'epmpcg'

            DATA = 'data'
            NAME = 'name'
            MEM_PCT = 'memLimitPercent'

            NAME_OTHER = 'Other'
        PCG = Epmpcg()
    EPM = Epm()


XDB = XosDB()

# ############################################################
# Logging
# ############################################################
LOG_FILE = '/usr/local/tmp/logs/clone.txt'
try:
    mkdir(dirname(LOG_FILE), 0777)
except Exception:
    pass
try:
    chown(dirname(LOG_FILE), 0777)
except Exception:
    pass
log_hdl = logging.StreamHandler(sys.stderr)
log_hdl.setLevel(logging.INFO)
log_hdl.setFormatter(logging.Formatter(
    '%(levelname)s:%(threadName)s:%(name)s:%(funcName)s:%(lineno)s: '
    '%(message)s'))
log = logging.getLogger(XDB.PROCESS_NAME)
log.setLevel(logging.INFO)
if not len(log.handlers):
    log.addHandler(log_hdl)


# ############################################################
# Communicate with the remote systemsync agent on VR-Control
# ############################################################
class ExosSync(object):
    # this object runs on a stack master to communicate with
    # the EXOS systemsync agent on a slot
    # see systemsync.c in the EXOS source tree for more information
    # on the systemsync agent.
    #
    # One class instance is created for each slot being sync-ed

    # systemsync op codes for
    class OpCodes(object):
        CMD_INIT = 1
        CMD_INIT_REPLY = 2
        CMD_STAT = 3
        CMD_STAT_REPLY = 4
        CMD_OPEN = 5
        CMD_OPEN_REPLY = 6
        CMD_LSEEK = 7
        CMD_LSEEK_REPLY = 8
        CMD_WRITE = 9
        CMD_WRITE_REPLY = 10
        CMD_READ = 11
        CMD_READ_REPLY = 12
        CMD_CLOSE = 13
        CMD_CLOSE_REPLY = 14
        CMD_SYNC = 15
        CMD_SYNC_REPLY = 16
        CMD_REBOOT = 17
        CMD_SYSTEM = 18
        CMD_SYSTEM_REPLY = 19
    OP = OpCodes()

    VERSION = '2.0'

    def __init__(self, slot):
        self.sock = None
        self.sizeof_long = len(struct.pack('L', 0))
        self.vr = 1
        self.slot = slot

    def version(self):
        # the master asks the remote slot what it's systemsync version is

        self.remote_connect()

        # constuct a binary message to send to the remote slot
        # return the version of the remote system
        msg = bytearray()
        msg.extend(struct.pack('L', self.sizeof_long))
        msg.extend(struct.pack('L', ExosSync.OP.CMD_INIT))

        self.sock.settimeout(2)
        try:
            if len(msg) < 100:
                log.debug(binascii.hexlify(msg))
            self.sock.sendall(msg)
        except Exception as e:
            log.debug(str(e))
            return None

        # the remote slot responded
        reply = self.sock.recv(512)
        log.debug('recv {}'.format(binascii.hexlify(reply)))

        # the data is in binary packed format
        offset = 0

        # unpack the message length
        slen = struct.unpack_from('L', reply, offset)[0]
        offset += self.sizeof_long
        payload_len = (slen - offset)

        # unpack the message type
        rtype = struct.unpack_from('L', reply, offset)[0]
        if rtype != ExosSync.OP.CMD_INIT_REPLY:
            log.debug('Wrong message type returned for version {}'.format(rtype))
            return None

        offset += self.sizeof_long

        # unpack the version string
        fmt = '{}s'.format(payload_len)
        c_version = struct.unpack_from(fmt, reply, offset)[0]
        offset += payload_len

        log.debug('version is {}'.format(c_version))
        self.close()

        return c_version.rstrip('\0')

    def remote_send_recv(
            self,
            msg,
            send_timeout,
            reply_type,
            recv_timeout,
            dont_open=False,
            dont_close=False
            ):
        # this function is common for all transactions
        # It connects to the remote system, sends the mesage
        # and then closes the connection.
        # if dont_open is True, the connection has already been created
        #   and we should use the existing connection
        # if dont_close is True, the connect needs to remain open after
        #   sending/receiving this transactions
        #

        if dont_open is False:
            self.remote_connect()

        if len(msg) < 100:
            # limit debug output to something that can be visually seen
            log.debug('sending {}'.format(binascii.hexlify(msg)))

        self.sock.settimeout(send_timeout)

        # send the message to the remote slot systemsync agent
        try:
            self.sock.sendall(msg)
        except Exception as e:
            log.debug(str(e))
            self.close()
            return None, None

        self.sock.settimeout(recv_timeout)  # 5 minutes

        # wait here for the slot systemsync agent to respond
        reply = self.sock.recv(512)

        offset = 0

        # unpack the message length
        offset += self.sizeof_long

        # unpack the message type
        rtype = struct.unpack_from('L', reply, offset)[0]
        if rtype != reply_type:
            log.debug('Wrong message type returned. Expected={} received={}'.format(
                reply_type,
                rtype))
            self.close()
            return None, None

        # unpack the rc
        rc = struct.unpack_from('l', reply, offset)[0]
        offset += self.sizeof_long

        # unpack the rc_errno
        rc_errno = struct.unpack_from('l', reply, offset)[0]
        offset += self.sizeof_long

        log.debug('remote_recv = {},{}'.format(rc, rc_errno))

        # check if the connection should be left open
        if dont_close is False:
            self.close()

        return rc, rc_errno

    def copy(self, local_filename, remote_filename):
        # copy a file on the local system to the remote system
        # this is a higher level function that uses these functions to
        # copy a file from the local system to the remote system
        #   remote_open()
        #   remote_write()
        #   remote_close()

        log.debug('copy {} to remote {}'.format(local_filename, remote_filename))

        with open(local_filename, 'r') as fd:
            # flags = C O_CREAT|O_WRONLY|O_TRUNC and -rwr--r--
            rc, rc_errno = self.remote_open(
                    remote_filename,
                    O_CREAT | O_WRONLY | O_TRUNC,
                    0644)
            if rc < 0:
                raise IOError

            # read the local file in chunks and send it to the remote system
            while True:
                # read chunks
                data = fd.read(8*1024)
                if len(data) == 0:
                    break
                # write to the remote system
                rc, rc_errno = self.remote_write(data)
                if rc < 0:
                    log.debug('remote_write failed {},{}'.format(rc, rc_errno))

            rc, rc_errno = self.remote_close()

    def system(self, cmd, expect_error=False):
        # run a linux(system) command on the remote system
        # and return the result code

        log.debug(cmd)

        # create a command message to send to the remote systemsync server
        msg = bytearray()
        msg.extend(struct.pack('L', (2 * self.sizeof_long) + len(cmd) + 1))
        msg.extend(struct.pack('L', ExosSync.OP.CMD_SYSTEM))
        msg.extend(struct.pack('L', len(cmd) + 1))
        fmt = '{}s'.format(len(cmd) + 1)  # pack will zero fill (null termination)
        msg.extend(struct.pack(fmt, cmd))

        # get the response from the remote system
        try:
            rc, rc_errno = self.remote_send_recv(msg, 3, ExosSync.OP.CMD_SYSTEM_REPLY, 15*60)
        except socket_timeout as timeout_err:
            # if the socket operation (send/recv) times out, raise the exception
            log.debug('Remote system command "{}" timed out on slot {}'.format(cmd, self.slot))
            raise
        except Exception:
            # if a system command, such as reboot, causes a socket error
            # that's OK
            if expect_error is True:
                return None, None
            raise

        return rc, rc_errno

    def remote_connect(self):
        # connect to the systemsync agent on <slot> and verify that it
        # is running version 2.0

        # VR-Control ipaddress format for slots
        ip = '10.0.{}.2'.format(self.slot)
        # socket for remote systemsync agents
        addr = (ip, 888)

        environ["EXOS_VR_ID"] = str(1)
        self.sock = socket(AF_INET, SOCK_STREAM)
        # VR-Control = 1
        self.sock.setsockopt(SOL_SOCKET, 37, 1)

        # if we don't connect in 2 seconds, something is wrong
        self.sock.settimeout(2)

        log.debug('Trying to connect to {} vr {}'.format(addr, self.vr))

        # connect to the remote systemsync agent
        try:
            self.sock.connect(addr)
        except Exception as msg:
            print 'Cannot connect to slot', msg

    def close(self):
        # close the connection to the systemsync agent on the remote system
        self.sock.close()
        self.sock = None

    def remote_open(self, remote_filename, flags, mode):
        # send the remote agent a transaction to open a file
        msg = bytearray()
        msg.extend(struct.pack('L', (3 * self.sizeof_long) + len(remote_filename) + 1))
        msg.extend(struct.pack('L', ExosSync.OP.CMD_OPEN))
        msg.extend(struct.pack('L', flags))
        msg.extend(struct.pack('L', mode))
        fmt = '{}s'.format(len(remote_filename) + 1)  # pack will zero fill for NULL
        msg.extend(struct.pack(fmt, remote_filename))

        return self.remote_send_recv(msg, 3, ExosSync.OP.CMD_OPEN_REPLY, 3, dont_close=True)

    def remote_write(self, data):
        # send the remote agent a transaction to write data to a file
        msg = bytearray()
        msg.extend(struct.pack('L', (2 * self.sizeof_long) + len(data)))
        msg.extend(struct.pack('L', ExosSync.OP.CMD_WRITE))
        msg.extend(struct.pack('L', len(data)))
        fmt = '{}s'.format(len(data))
        msg.extend(struct.pack(fmt, data))

        return self.remote_send_recv(
                msg,
                3,
                ExosSync.OP.CMD_WRITE_REPLY,
                3,
                dont_open=True,
                dont_close=True)

    def remote_close(self):
        # send the remote agent a transaction to close a file
        msg = bytearray()
        msg.extend(struct.pack('L', self.sizeof_long))
        msg.extend(struct.pack('L', ExosSync.OP.CMD_CLOSE))

        return self.remote_send_recv(msg, 3, ExosSync.OP.CMD_CLOSE_REPLY, 3, dont_open=True)

    #
    # factory function to verify connectivity with a list of slot numbers
    #
    @staticmethod
    def compatible_stacking_slots(slot_list):
        # contact each slot to see if it supports cloning 2.0
        # this function supports the CLI command
        #   run script clone.py slot <>
        # this option is run from a stack master
        if not slot_list:
            return slot_list

        # contact the systemsync agent on each slot over VR-Control
        sock_list_out = []
        for slot in slot_list:
            ip = '10.0.{}.2'.format(slot)
            addr = (ip, 888)
            environ["EXOS_VR_ID"] = str(1)
            sock = socket(AF_INET, SOCK_STREAM)
            sock.setsockopt(SOL_SOCKET, 37, 1)
            sock.settimeout(2)
            try:
                sock.connect(addr)
            except Exception as e:
                log.debug('Cannot connect to slot {}, addr {}'.format(slot, addr))
                continue

            # get the identity/version of the systemsync agent on the slot
            msg = bytearray()
            msg.extend(struct.pack('L', 4))
            msg.extend(struct.pack('L', 1))

            sock.sendall(msg)

            # get the response from the identiy request
            try:
                reply = sock.recv(512)
            except Exception as e:
                log.debug('receive from {} failed: {}'.format(addr, str(e)))
                continue
            offset = 0

            slen = struct.unpack_from('L', reply, offset)[0]
            offset += 4
            payload_len = (slen - offset)

            struct.unpack_from('L', reply, offset)[0]
            offset += 4

            fmt = '{}s'.format(payload_len)  # subtract trailing null for string
            c_version = struct.unpack_from(fmt, reply, offset)[0]
            offset += payload_len

            log.debug('version from {} is {}'.format(addr, c_version))
            version_parts = c_version.split('\0')
            if len(version_parts) and version_parts[0] == '2.0':
                sock_list_out.append(slot)
            sock.close()

        return sock_list_out


# ####################################################################
# Sync NVRAM to Master
# ####################################################################
class NvramSync(object):
    # this class manages the nvram on the local switch
    # The NVRAM is a sequents of TLV (Type, Length, Value) objects
    # The EXOS NVRAM can be accessed by reading/writing /dev/exosNvram

    class Nvram(object):
        EOI_INFO = 0x8005
        STACK_INFO = 0x8059
        PORT_PARTITION_INFO = 0x8073
        EPM_RESTART_INFO = 0x802D
        BOOT_PARTITION_INFO = 0x8033
        REBOOT_COUNT_INFO = 0x8057
        CM_CONFIG_FILENAME_INFO = 0x8031
        CLI_BANNER_INFO = 0x8040
        CLI_BANNER_ACK_INFO = 0x8058
        CLI_SCRIPTING_STATUS_INO = 0x805A
        INTERNAL_SWITCH_MEMORY_MODE_INFO = 0x8080
        NODE_MGR_CONFIG_INFO = 0x8030
        SHUTDOWN_FLAG_INFO = 0x8055
        SYSLOG_INFO = 0x8022
        FAILSAFE_USERNAME_INFO = 0x8083
        FAILSAFE_PASSWORD_INFO = 0x8084
        FAILSAFE_ACCESS_INFO = 0x8085
        BOOT_MODE_FLAG_INFO = 0x8087
        # stored in eeprom
        SSH_CFG_INFO = 0x805C
        SSH_CFG_NEW_INFO = 0x807f
        SSL_CFG_INFO = 0x8044
    NV = Nvram()

    def __init__(self):
        # compute comment object lengths here so we don't use constants
        self.sizeof_short = len(struct.pack('H', 0))
        self.sizeof_uint = len(struct.pack('I', 0))
        self.sizeof_ulonglong = len(struct.pack('Q', 0))
        # keep a local copy of values we update in NVRAM for other parts of clone.py
        self.nvram_dict = {}

    def download_remote_nvram(self, remote_fd):
        # communicating with clone.py master, download the nvram contents
        # from the master
        if isinstance(remote_fd, socket):
            buf = bytearray()
            while True:
                chunk = remote_fd.recv(8192)
                if len(chunk):
                    buf += chunk
                    continue
                break
        else:
            buf = bytearray(remote_fd.read())

        log.debug('Remote NVRAM read {} bytes'.format(len(buf)))
        return buf

    def read_local_nvram(self, fd):
        return bytearray(fd.read())

    def clone_common_objects(self, remote_fd, local_fd, exos_only=False):
        # This is the control function that coordinates which objects
        # are copied from the remote master to the local client NVRAM
        remote_nvram = self.download_remote_nvram(remote_fd)
        local_fd.seek(0)
        local_nvram = self.read_local_nvram(local_fd)
        log.debug('local NVRAM read {} bytes'.format(len(local_nvram)))

        # This is a list of TLVs that are copied from the remote master
        # into the local client NVRAM TLV object
        nvram_common_obj_list = [
                NvramSync.NV.BOOT_PARTITION_INFO,
                NvramSync.NV.CLI_BANNER_INFO,
                NvramSync.NV.FAILSAFE_USERNAME_INFO,
                NvramSync.NV.FAILSAFE_PASSWORD_INFO,
                NvramSync.NV.FAILSAFE_ACCESS_INFO,
                NvramSync.NV.BOOT_MODE_FLAG_INFO,
                ]
        if exos_only is False:
            nvram_common_obj_list.append(NvramSync.NV.CM_CONFIG_FILENAME_INFO)

        for tlv_type in nvram_common_obj_list:
            self.update_local_tlv(tlv_type, remote_nvram, local_nvram, local_fd)
        return self.nvram_dict

    def clone_eeprom_objects(self, remote_fd, local_fd, exos_only=False):
        # This is the control function that coordinates which objects
        # are copied from the remote master to the local client EEPROM
        remote_nvram = self.download_remote_nvram(remote_fd)
        local_fd.seek(0)
        local_nvram = self.read_local_nvram(local_fd)
        log.debug('local EEPROM read {} bytes'.format(len(local_nvram)))

        # This is a list of TLVs that are copied from the remote master
        # into the local client NVRAM TLV object
        nvram_common_obj_list = [
                NvramSync.NV.SSH_CFG_INFO,
                NvramSync.NV.SSH_CFG_NEW_INFO,
                # NvramSync.NV.SSL_CFG_INFO,
                ]

        for tlv_type in nvram_common_obj_list:
            self.update_local_tlv(tlv_type, remote_nvram, local_nvram, local_fd)
            # reload the eeprom image in case there were additions
            local_fd.seek(0)
            local_nvram = self.read_local_nvram(local_fd)
            log.debug('local EEPROM read {} bytes'.format(len(local_nvram)))
        return self.nvram_dict

    def update_local_tlv(self, tlv_type, remote_nvram, local_nvram, local_fd):
        # search for the TLV type and copy the remote TLV to local

        # find the tlv type in the remote NVRAM image and return the length and offset
        try:
            rmt_type, rmt_len, rmt_value, rmt_value_offset = self.find_tlv_len_offset(
                    tlv_type,
                    remote_nvram)
        except Exception as e:
            log.error('nvram corruption from the remote system {}'.format(e))
            return
        # find the tlv type in the local NVRAM image and return the length and offset
        try:
            lcl_type, lcl_len, lcl_value, lcl_value_offset = self.find_tlv_len_offset(
                    tlv_type,
                    local_nvram)
        except Exception as e:
            log.error('nvram corruption on the local system {}'.format(e))
            return
        # TLV does not exist on remote or local system
        if rmt_type is None and lcl_type is None:
            return

        # if the remote TLV does not exist, clear the local TLV
        if rmt_type is None:
            rmt_value = bytearray(lcl_len)
            log.debug('rmt_type={} not found locally. Clearing local object {} at offset {}'.format(
                rmt_type,
                lcl_type,
                lcl_value_offset))
        # if local object does not exist, create it
        elif lcl_type is None:
            log.debug('lcl_type={} not found. Adding it'.format(tlv_type))
            self.add_tlv(rmt_type, rmt_len, rmt_value, local_nvram, local_fd)
            return

        log.debug('lcl_type={}, lcl_len={}, lcl_value={}, lcl_value_offset={}'.format(
            lcl_type,
            lcl_len,
            lcl_value,
            lcl_value_offset))

        # keep a local copy for reference
        log.debug('tlv_type={}, lcl_value={}'.format(hex(tlv_type), lcl_value))
        self.nvram_dict[tlv_type] = lcl_value

        # open the local nvram device
        log.debug('updating NVRAM object {} at offset {}'.format(
            hex(lcl_type), hex(lcl_value_offset)))
        if len(rmt_value) < 100:
            log.debug(binascii.hexlify(rmt_value))

        # copy the TLV value from the remote NVRAM to the local NVRAM device
        # the entire value field is copied.
        local_fd.seek(lcl_value_offset)
        local_fd.write(rmt_value)
        local_fd.flush()
        return

    def find_tlv_len_offset(self, tlv_type_in, nvram):
        # this function walks the TLV list looking for a match on tlv_type
        # once found, return the Type,Len,Value and offset
        offset = 0
        while True:
            if offset >= len(nvram):
                return None, None, None, None

            # extract the TLV type
            val = str(nvram[offset:offset+self.sizeof_short])
            tlv_type = struct.unpack('!H', val)[0]
            offset += self.sizeof_short

            # extract the TLV len
            val = str(nvram[offset:offset+self.sizeof_short])
            tlv_len = struct.unpack('!H', val)[0]
            offset += self.sizeof_short

            # extract the TLV value
            val = str(nvram[offset:offset+tlv_len])
            fmt = '{}s'.format(tlv_len)
            tlv_value = struct.unpack(fmt, val)[0]

            # is it the one we are looking for?
            if tlv_type_in == tlv_type:
                log.debug('Offset {}, T={}, L={}, formatV={}'.format(
                    offset, hex(tlv_type), tlv_len, fmt))

                # limit the output to values < 100 bytes
                if tlv_len < 100:
                    log.debug(binascii.hexlify(tlv_value))

                # return the TLV information found
                return tlv_type, tlv_len, tlv_value, offset

            offset += tlv_len
            # if the EOI object is found, we are at the end of NVRAM TLVs
            if tlv_type == NvramSync.NV.EOI_INFO:
                return None, None, None, None

    def add_tlv(self, tlv_type_in, tlv_len_in, tlv_value_in, nvram, local_fd):
        # find the tlv type in the local NVRAM image and return the length and offset
        tlv_type, tlv_len, tlv_value, value_offset = self.find_tlv_len_offset(NvramSync.NV.EOI_INFO,
                                                                              nvram)
        tlv = bytearray()
        tlv += struct.pack('!H', tlv_type_in)
        tlv += struct.pack('!H', tlv_len_in)
        tlv += struct.pack('{}s'.format(tlv_len_in), tlv_value_in)
        tlv += struct.pack('!H', tlv_type)
        tlv += struct.pack('!H', tlv_len)
        tlv += struct.pack('{}s'.format(tlv_len), tlv_value)

        # back up to point to type field
        offset = value_offset - 4
        local_fd.seek(offset)
        local_fd.write(tlv)
        local_fd.flush()


# **********************************************************************
# This is a class for manipulating tar files
# **********************************************************************
class ExpyTar(object):
    def __init__(self):
        self.path = None
        self.mode = None
        self.fd = None

    @staticmethod
    def is_tar(path):
        log.debug(path)
        return tar.is_tarfile(path)

    def open(self, path=None, mode=None):
        log.debug('{} {}'.format(path, mode))
        self.fd = tar.TarFile.open(path, mode)
        return self.fd

    def close(self):
        self.fd.close()

    def open_file(self, path):
        log.debug(path)
        return self.fd.extractfile(path)

    @staticmethod
    def _extract_members(fd, include=None, exclude=None):
        if include:
            re_include = re_compile(include)
        else:
            re_include = None

        if exclude:
            re_exclude = re_compile(exclude)
        else:
            re_exclude = None

        for tarinfo in fd.getmembers():
            # an include parameter was provided, check for a match
            if re_include and re_include.search(tarinfo.name) is None:
                continue

            # either there is no include selection (all names) or
            # a name matched the include, check if it matches the exclude
            # i.e. include a large set of filenames but exclude a specific file
            if re_exclude and re_exclude.search(tarinfo.name):
                continue

            # passed both include and exclude filters
            yield tarinfo

    def extract(self, dst_path='.', include=None, exclude=None):
        log.debug('dst_path={} include={} exclude={}'.format(dst_path, include, exclude))
        if include or exclude:
            self.fd.extractall(
                path=dst_path,
                members=self._extract_members(self.fd, include, exclude))
        else:
            self.fd.extractall(path=dst_path, members=self.fd.members)


# **********************************************************************
# This is a common class for both script and expy env
# **********************************************************************
class CloneCommonBase(object):
    # this class is shared by both run script context and expy context
    # functions in this clas are interited by the other classes

    def __init__(self):
        self.vr = 0
        self.args = None
        self.dm_dict = None
        self.stop_dots = None
        self.stk_mstr = None

    @staticmethod
    def system_call(cmd, suppress_output=False):
        if isinstance(cmd, list):
            cmd = ';'.join(cmd)
        log.debug(cmd)
        out_fd = None
        if suppress_output is True:
            out_fd = open('/dev/null', 'r+')
        try:
            subprocess_check_call(cmd, stdout=out_fd, shell=True)
            rslt = True
        except subprocess_CalledProcessError as e:
            log.error('{} command failed'.format(e.cmd))
            rslt = False
        if out_fd:
            out_fd.close()
        return rslt

    @staticmethod
    def exos_shell(cmd):
        log.debug(cmd)
        exos_cmd = '/exos/bin/exsh -n 0 -b -c "{}"'.format(cmd)
        try:
            log.debug(exos_cmd)
            subprocess_check_call(exos_cmd, shell=True)
            return True
        except subprocess_CalledProcessError as e:
            log.error('{} command failed'.format(e.cmd))
            return False

    @staticmethod
    def display_box(msg, border='*', width=None):
        # format a list of text messages surrounded by a box
        if width is None:
            max_col = 0
            for l in msg:
                if len(l) > max_col:
                    max_col = len(l)
            max_col += 4
        else:
            max_col = width

        print
        print border * (max_col + 4)
        for l in msg:
            print '{border} {txt:^{col}} {border}'.format(border=border, txt=l, col=max_col)
        print border * (max_col + 4)

    @staticmethod
    def get_yes_no():
        while True:
            yes_no = raw_input('Do you want to continue cloning? [y/N]: ').strip().lower()
            log.debug(yes_no)
            if yes_no not in ['', 'y', 'yes', 'n', 'no']:
                print 'unknown input', yes_no
                continue
            if len(yes_no) and yes_no[0] == 'y':
                return True
            break

        return False

    def is_process_running(self):
        # access the EPM information and see if we are already in the process
        # list
        cmd = 'debug cfgmgr show one {module}.{block} {field}={proc}'.format(
            module=XDB.EPM.MODULE,
            block=XDB.EPM.PCB.BLOCK,
            field=XDB.EPM.PCB.NAME,
            proc=XDB.PROCESS_NAME)

        reply = self.exos_clicmd(cmd)
        try:
            data = json_loads(reply)
        except TypeError:
            return False
        block = data.get(XDB.EPM.PCB.DATA)[0]
        process_pid = block.get(XDB.EPM.PCB.PID)

        if process_pid is None:
            return False
        return True

    def process_group_limit(self):
        # when c-groups was introduced, it constantly tried to shut down the cloning
        # process because the memeory allocation is very small.
        # lets bump it up so we don't run into that issue
        cmd = 'debug cfgmgr show one {module}.{block} {field}={proc}'.format(
            module=XDB.EPM.MODULE,
            block=XDB.EPM.PCG.BLOCK,
            field=XDB.EPM.PCG.NAME,
            proc=XDB.EPM.PCG.NAME_OTHER)

        reply = self.exos_clicmd(cmd)
        try:
            data = json_loads(reply)
            block = data.get(XDB.EPM.PCG.DATA)[0]
            mem_pct = block.get(XDB.EPM.PCG.MEM_PCT)
        except Exception:
            return None

        if mem_pct is None:
            return None
        return int(mem_pct)

    def process_cleanup(self, reboot=False):
        # If the cloning server is running, delete the process from EXOS

        log.debug('Called reboot={}'.format(reboot))

        while self.is_process_running() is True:
            # clean up any leftovers just in case
            # or possibly the command is already running on a second session
            cmd_list = []
            cmd_list.append('delete process {0}'.format(XDB.PROCESS_NAME))
            cmd_list.append('unconfig mgmt ip'.format(XDB.PROCESS_NAME))
            cmd_list.append('unconfig default ip'.format(XDB.PROCESS_NAME))
            self.exos_clicmd(cmd_list)
            sleep(3)

        # We can ask for a linux reboot after we delete the cloning process
        if reboot is True:
            try:
                subprocess_check_call('sync;sync;reboot -f', shell=True)
            except subprocess_CalledProcessError as e:
                log.debug('{} command failed'.format(e.cmd))

    def set_log_level(self):
        # turn on debugging if in the sys.args
        # logging to file so we capture all debug
        if self.args.debug:
            log_hdl.setLevel(logging.DEBUG)
            log.setLevel(logging.DEBUG)

    def get_serial_number(self):
        # get the dm module from CM. It contains the serial number
        reply = self.exos_clicmd(
            'debug cfgmgr show one dm.sysCommon')

        try:
            dm_dict = json_loads(reply).get('data')[0]
        except Exception as msg:
            log.debug(
                'Error getting dm.dm_system:{}:{}'.format(msg, reply))
            return None
        return dm_dict.get('extremeSystemID').split()[1]

    def get_vlan_ip(self, vlan_name):
        # find vlan by name and return the IP address assigned to it
        # the value will be 0.0.0.0 if there is no IP assigned
        cmd = 'debug cfgmgr show one vlan.vlanProc action=SHOW_VLAN_NAME_GET_IP_ADDR name1={}'.format(vlan_name)
        reply = self.exos_clicmd(cmd)

        try:
            reply_dict = json_loads(reply).get('data')[0]
        except Exception as msg:
            log.debug(
                'Error getting vlan.vlanProc:{}:{}'.format(msg, reply))
            return None
        return reply_dict.get('ipAddress')

    def get_dm_system(self):
        # get the dm module from CM.
        # the client sends the information to the master so it knows what type of switch
        # the client is
        if self.dm_dict:
            return self.dm_dict

        reply = self.exos_clicmd('debug cfgmgr show one dm.dm_system')

        # the EXOS resonse will be CM data in JSON format
        try:
            self.dm_dict = json_loads(reply).get('data')[0]
        except Exception as msg:
            log.debug(
                'Error getting dm.dm_system:{}:{}'.format(msg, reply))
            return None

        return self.dm_dict

    def is_stacking_enabled(self):
        # look for the environment varialbe that tells us if stacking is enabled
        log.debug('EXOS_STACK_MODE = {}'.format(getenv('EXOS_STACK_MODE')))
        return True if getenv('EXOS_STACK_MODE') == '1' else False

    def is_stack_master(self):
        # return cached results of previous query
        if self.stk_mstr is not None:
            return self.stk_mstr
        # Ask EXOS for stacking information the tells us if this switch
        # is a stack master
        cmd = 'debug cfgmgr show next hal.stackingShowInfo'
        reply = self.exos_clicmd(cmd)

        try:
            reply_dict = json_loads(reply).get('data')[0]
        except Exception as msg:
            log.debug(
                'Error getting hal.stackingShowInfo:{}:{}'.format(msg, reply))
            return None
        log.debug('host_is_master = {}'.format(reply_dict.get('host_is_master')))
        self.stk_mstr = True if reply_dict.get('host_is_master') == '1' else False
        return self.stk_mstr

    def get_my_slot(self):
        # look for the environment varialbe that tells us our slot number
        return getenv('EXOS_STACK_SLOT')

    def get_slot_list(self):
        if self.is_stacking_enabled():
            return self.get_stacking_slot_list()
        return self.get_standalone_slot_list()

    def get_stacking_slot_list(self):
        # create a list of slot numbers where the slot
        # farthest from the master is first in the list
        myslot = self.get_my_slot()
        cmd = 'debug cfgmgr show next hal.stackingShowStack'
        reply = self.exos_clicmd(cmd)
        try:
            reply_list = json_loads(reply).get('data')
        except Exception as msg:
            log.debug(
                'Error getting hal.stackingShowStack:{}:{}'.format(msg, reply))
            return []

        # this bit of code handles a slot list that has slots before and
        # after the master
        # e.g.  4,3,2,1,5,6,7,8 where 1 is the master
        # first extract 4,3,1, then extract 8,7,6,5
        slot_list = []
        for stack_list in [reply_list, reversed(reply_list)]:
            for reply_dict in stack_list:
                slot = reply_dict.get('slot')
                if slot == myslot:
                    break
                slot_list.append(slot)
        return slot_list

    def get_standalone_slot_list(self):
        # create a list of slot information entries
        # on a standalone system this will be a single entry
        myslot = self.get_my_slot()
        cmd = 'debug cfgmgr show next dm.card_info slot=None'
        reply = self.exos_clicmd(cmd)

        try:
            reply_list = json_loads(reply).get('data')
        except Exception as msg:
            log.debug(
                'Error getting dm.card_info:{}:{}'.format(msg, reply))
            return []

        slot_list = []
        for reply_dict in reply_list:
            card_state = reply_dict.get('card_state')
            slot = reply_dict.get('slot')
            if slot == myslot:
                continue
            if card_state not in ['1', None]:
                slot_list.append(slot)
        log.debug(slot_list)
        return slot_list

    def progress_dots_thread(self):
        # this function displays progress dots every 2 seconds to entertain the user
        while True:
            sleep(2)
            if self.stop_dots is True:
                return
            try:
                sys.stdout.write('.')
                sys.stdout.flush()
            except Exception:
                pass

    def start_progress_dots(self, slot):
        # start the progress dots thread
        self.stop_dots = False
        dots = threading.Thread(
            target=self.progress_dots_thread,
            name='dots'.format(slot))
        dots.daemon = True
        dots.start()
        return dots

    def stop_progress_dots(self):
        # tell the progress dots thread to stop
        self.stop_dots = True

    # converts a comma separated, list of number ranges into individual values
    # man_range - if provided, checks the input against an lower value
    # max_range - if provided, checks the input against an upper value
    # E.g. input is a string: 1,2,3-6,10,20
    @staticmethod
    def range_check(input_str, min_range=None, max_range=None):
        if isinstance(input_str, str) and input_str:
            pass
        else:
            raise ValueError('Input must be a non-zero length string: {}'.format(
                input_str))

        out_set = set()

        # split input string into comma separated parts
        comma_parts = input_str.split(',')
        for comma_part in comma_parts:

            # skip over ,, as a non issue
            if len(comma_part) == 0:
                continue

            # split each part into it's range
            dash_parts = comma_part.split('-')
            if len(dash_parts) > 2:
                raise ValueError('Invalid range format: {}'.format(comma_part))

            # validate input as numeric and in range: min <= x <= max
            for dash_part in dash_parts:
                if not dash_part.isdigit():
                    raise ValueError('Value is not a number: {}'.format(comma_part))
                if min_range and int(dash_part) < min_range:
                    raise ValueError('Valuee is less than min range: {} < {}'.format(
                        comma_part, min_range))
                if max_range and int(dash_part) > max_range:
                    raise ValueError('Value is greater than max range: {} > {}'.format(
                        comma_part, max_range))

            # build a numeric range
            dash_begin = int(dash_parts[0])
            dash_end = int(dash_parts[-1])

            # validate the range begin <= end
            if dash_begin > dash_end:
                raise ValueError('Invalid reversed range: {}'.format(comma_part))

            # create individual non-overlaping values using a set()
            for v in xrange(dash_begin, dash_end + 1):
                out_set.add(v)

        return sorted(out_set)

    @staticmethod
    def is_onie_device():
        try:
            if int(environ.get('EXOS_ONIE_GRUB')) == 1:
                return True
            return False
        except Exception:
            return False

    def stop_hal(self):
        # only stop the hal proces if we are cloning the stacking master
        if self.is_stack_master():
            reply = subprocess_check_output('ps | grep hal | grep -v grep', shell=True)
            log.debug(reply)
            reply_parts = reply.split()
            if self.is_onie_device():
                SIGSTOP = -19
            else:
                SIGSTOP = -23
            self.system_call('kill {} {}'.format(SIGSTOP, reply_parts[0]))

    @staticmethod
    def strip_alpha_from_version(av):
        # For our purposes, just ignore everything that follows
        # the first non-numeric character in the version string
        # i.e. 30.2.1.8-patch2-4 ==> 30.2.1.8
        m = re_search('(^[.0-9]+)', av)

        # Handle the case where the sub-version started with
        # a non-numeric.  Bump it up to max.
        return re_sub('\.$', '.99999', m.group(0))

    @staticmethod
    def compare_versions(version1, version2):
        try:
            v1 = [int(x) for x in version1.split('.')]
        except:
            tv = CloneCommonBase.strip_alpha_from_version(version1)
            v1 = [int(x) for x in tv.split('.')]
            log.debug('converting version {} ==> {}'.format(version1, tv))
        try:
            v2 = [int(x) for x in version2.split('.')]
        except:
            tv = CloneCommonBase.strip_alpha_from_version(version2)
            v2 = [int(x) for x in tv.split('.')]
            log.debug('converting version {} ==> {}'.format(version2, tv))
        for i in range(len(v1)):
            if i >= len(v2):
                return XDB.CMP_GREATER_THAN
            elif v1[i] > v2[i]:
                return XDB.CMP_GREATER_THAN
            elif v1[i] < v2[i]:
                return XDB.CMP_LESSER_THAN
        if len(v2) > len(v1):
            return XDB.CMP_LESSER_THAN
        return XDB.CMP_EQUAL

    def is_block_root(self, dm_sysCommon):
        if ( self.compare_versions(
                dm_sysCommon.get('extremePrimarySoftwareRev'),
                '30.3.0.0') == XDB.CMP_GREATER_THAN
             and
             self.compare_versions(
                dm_sysCommon.get('extremeSecondarySoftwareRev'),
                '30.3.0.0') == XDB.CMP_GREATER_THAN ):
            return (True, True)
        elif ( self.compare_versions(
                  dm_sysCommon.get('extremePrimarySoftwareRev'),
                  '30.3.0.0') == XDB.CMP_LESSER_THAN
             and
             self.compare_versions(
                dm_sysCommon.get('extremeSecondarySoftwareRev'),
                '30.3.0.0') == XDB.CMP_LESSER_THAN ):
            return (False, True)
        elif ( self.compare_versions(
                  dm_sysCommon.get('extremePrimarySoftwareRev'),
                  '30.3.0.0') == XDB.CMP_GREATER_THAN
             or
             self.compare_versions(
                dm_sysCommon.get('extremeSecondarySoftwareRev'),
                '30.3.0.0') == XDB.CMP_GREATER_THAN ):
            return (True, False)
        else:
            return (False, False)

    @staticmethod
    def stage_active_root(root_hash):
        with open(XDB.STAGED_ROOT, 'w') as f:
            f.write('{}'.format(root_hash))


# **********************************************************************
# This class is invoked in the expy context via the EXOS CLI: create process
# **********************************************************************
class CloneBaseExpy(CloneCommonBase):
    # This class is shared by the EXOS expy process.
    # functions in this class are common to both master and client

    # the JsonRPC constants are used to format the request part of the transacitons
    # between the client and master. The stucture just needs to be consistent so
    # JSONRPC format is used, for the request half of the transaction.
    # The response varies depending on the request.

    # Client JSONRPC request -> Master
    class JsonRPC(object):
        JSONRPC = 'jsonrpc'
        METHOD = 'method'
        ID = 'id'
        PARAMS = 'params'
        CLONE_VERSION = 'vClone'
    JSONRPC = JsonRPC()

    def __init__(self):
        # these variables are inherited by any sub-class
        super(CloneBaseExpy, self).__init__()
        self.jsonrpc_id = 1
        self.sock = None
        self.addr = None
        self.active_partition = None
        self.cwd = '/'

    def stacking_slot(self, slots):
        if slots == 'all':
            return slots
        try:
            return self.range_check(slots, 0, 8)
        except Exception as msg:
            print 'Slot:', msg
            raise

    def get_params(self):
        # These are the command line options for clone
        # Both master and client options are evalated here
        parser = argparse_ArgumentParser(prog=XDB.PROCESS_NAME)

        # backend role master/client/usb
        role_grp = parser.add_mutually_exclusive_group()
        role_grp.add_argument(
                '-m', '--master',
                help='Start cloning server',
                action='store_true',
                default=False)

        role_grp.add_argument(
                '-c', '--client',
                help='Start cloning client',
                action='store_true',
                default=False)

        role_grp.add_argument(
                '-u', '--usb',
                help='Start cloning USB',
                action='store_true',
                default=False)

        parser.add_argument(
                '-n', '--serialno',
                help='Serial number of clone master switch',
                default=None)

        # client options
        parser.add_argument(
                '-i', '--ipaddress',
                help='IP address of remote master',
                default=None)

        parser.add_argument(
                '-s', '--stacking_slot',
                help='Clone slot information of number of remote stack',
                type=self.stacking_slot,
                default=None)

        parser.add_argument(
                '-M', '--stacking_master',
                help='For stacking, enable this switch to be master_capable',
                action='store_true',
                default=False)

        parser.add_argument(
                '-e', '--exos_only',
                help='Only clone EXOS partitions. Do not clone the configuration',
                action='store_true',
                default=False)

        # usb options
        usb_options = parser.add_mutually_exclusive_group()
        usb_options.add_argument(
                '--usb_input',
                help='Clone from a file on USB memory',
                type=str,
                default=None)

        usb_options.add_argument(
                '--usb_output',
                help='Create clone file on USB memory',
                type=str,
                default=None)

        # master/client options
        parser.add_argument(
                '-v', '--virtual_router',
                help='Virtual router to use to contact master',
                type=int,
                default=0)

        parser.add_argument(
                '-d', '--debug',
                help='Show debug information',
                action='store_true',
                default=False)

        parser.add_argument(
                '--install',
                help='Install this application to both EXOS partitions',
                type=str,
                default=None)

        args = parser.parse_args()
        self.vr = args.virtual_router
        return args

    def __call__(self):
        # main function that determines if the command line options are for
        # a client or master
        try:
            self.args = self.get_params()
        except Exception as e:
            print str(e)
            raise

        self.cwd = getcwd()

        self.set_log_level()
        log.debug(self.args)

        # depending on the command line options, create a master or client process
        # if we are installing, this is the only action taken
        if self.args.install:
            self.expy_install()
        elif self.args.client is True:
            log.debug('Client')
            client = CloneClientExpy()
            client()
        elif self.args.master is True:
            log.debug('Master')
            master = CloneMasterExpy()
            master()
        elif self.args.usb is True:
            log.debug('usb')
            usb = CloneUsbExpy()
            usb()
        else:
            log.debug('No option selected')

    def exos_clicmd(self, cmd):
        # common function to communicate with EXOS CLI
        log.debug(cmd)
        try:
            if isinstance(cmd, list):
                reply = exec_cli(cmd)
            else:
                reply = exec_cli([str(cmd)])
        except Exception:
            return None

        try:
            reply_dict = json_loads(reply)
            log.debug(json_dumps(reply_dict, indent=2, sort_keys=True))
        except Exception:
            log.debug(reply)
        return reply

    def cm_startup(self):
        # in the EXOS environment, participating the the CM startup
        # shows the process as ready instead of LoadCfg
        # if self.is_stacking_enabled() is True:
        #    return
        log.debug('Called')
        if has_cm_backend is True:
            # The context for this class is the main expy thread
            # Callbacks invoke these class funcions
            # We pass in the our Clone Expy instance so it can reference
            # those functions/veriables directly
            class CloneCmAgent(CmAgent):

                def __init__(self, clone_expy):
                    self.clone_expy = clone_expy
                    super(CloneCmAgent, self).__init__()

                def event_load_start(self):
                    log.debug('Called event_load_start')

                def event_load_complete(self):
                    log.debug('Called event_load_complete')
                    ready()

                def event_save_start(self):
                    log.debug('Called event_save_start')

                def event_save_complete(self):
                    log.debug('Called event_save_complete')

                def event_generate_default(self):
                    log.debug('Called event_generate_default')
                    ready()

            cmbackend_init(CloneCmAgent(self), )

    def jsonrpc_remote_cli(self, cmd):
        # Construct a CLI request for the remote system using
        # the JSONRPC format.

        # the response data is sent over the socket and is
        # accumulated here before returning it to the calling
        # function
        self.jsonrpc_send(XDB.CLI, cmd)

        # collect chunks of response then aggregate them into
        # a single answer
        reply = str()
        while True:
            try:
                buf = self.sock.recv(4096)
                if len(buf):
                    reply += buf
                    continue
                break
            except Exception as msg:
                log.debug(msg)
                break

        # The reponse is expected to be JSON encoded
        try:
            reply_list = json_loads(reply).get('data')
        except Exception as msg:
            log.debug('Error getting data:{}:{}'.format(msg, reply))
            return None

        log.debug(json_dumps(reply_list, indent=2, sort_keys=True))

        # return the decoded JSON results
        return reply_list

    def jsonrpc_remote_shell(self, cmd):
        # Construct a CLI request for the remote system using
        # the JSONRPC format.

        # the response data is sent over the socket and is
        # accumulated here before returning it to the calling
        # function
        self.jsonrpc_send(XDB.SHELL, cmd)

        # collect chunks of response then aggregate them into
        # a single answer
        reply = str()
        while True:
            try:
                buf = self.sock.recv(4096)
                if len(buf):
                    reply += buf
                    continue
                break
            except Exception as msg:
                log.debug(msg)
                break

        return reply.splitlines()

    def jsonrpc_send(self, method, params):
        # client side method for sending JSONRPC requests
        self.sock, self.addr = self.connect_to_master()
        jsonrpc_rqst = {
            CloneBaseExpy.JSONRPC.JSONRPC: '2.0',
            CloneBaseExpy.JSONRPC.METHOD: method,
            CloneBaseExpy.JSONRPC.ID: self.jsonrpc_id,
            CloneBaseExpy.JSONRPC.PARAMS: params,
            CloneBaseExpy.JSONRPC.CLONE_VERSION: __version__
            }
        log.debug('Sending {}'.format(json_dumps(jsonrpc_rqst, indent=2, sort_keys=True)))
        self.sock.sendall(json_dumps(jsonrpc_rqst))
        self.jsonrpc_id += 1

    def jsonrpc_recv(self, conn):
        # master side method for receiving JSONRPC requests
        # no request is expected to be larger than 2000 bytes
        data = conn.recv(2000)

        # decode the JSONRPC request
        try:
            jsonrpc_dict = json_loads(data)
        except Exception as msg:
            # could be called by a rogue connection sending junk
            log.debug('master exception processing request {}'.format(msg))
            return (None, None, None)

        log.debug('jsonrpc received {}'.format(json_dumps(jsonrpc_dict, indent=2, sort_keys=True)))

        # check if the required fields are present in the request
        for f in [CloneBaseExpy.JSONRPC.JSONRPC,
                  CloneBaseExpy.JSONRPC.METHOD,
                  CloneBaseExpy.JSONRPC.ID,
                  CloneBaseExpy.JSONRPC.PARAMS]:
            if jsonrpc_dict.get(f) is None:
                log.debug('Missing input request parameter {}'.format(f))
                return (None, None, None)

        # The Clone Version field was introduced in 1.2.0.1.  If no version
        # is received, we'll stuff zeroes in.
        sender_version = jsonrpc_dict.get(CloneBaseExpy.JSONRPC.CLONE_VERSION)
        if sender_version is None:
            sender_version = '0.0.0.0'

        return (sender_version,
                jsonrpc_dict.get(CloneBaseExpy.JSONRPC.METHOD),
                jsonrpc_dict.get(CloneBaseExpy.JSONRPC.PARAMS))

    def read_preserve_file(self, root_dir, preserve_file_list):
        # create a dictionary of kept files
        # these are local files that will be restored after the remote clone
        if preserve_file_list is None:
            return
        # keep_file_dict entries are [filename] = StringIO object
        keep_file_dict = {}
        for fname in preserve_file_list:
            try:
                with open('{}{}'.format(root_dir, fname), 'r') as fd:
                    keep_file_dict[fname] = StringIO.StringIO(fd.read())
                    print '\nPreserving file', fname
            except Exception:
                continue
        if keep_file_dict:
            return keep_file_dict
        return None

    def write_preserve_file(self, root_dir, keep_file_dict):
        # restore a dictionary of kept files to the file system
        if keep_file_dict is None:
            return
        for fname, keep_fd in keep_file_dict.items():
            with open('{}{}'.format(root_dir, fname), 'w') as fd:
                fd.write(keep_fd.getvalue())
                keep_fd.close()
                print '\nRestoring file', fname

    def remove_preserve_file(self, root_dir, preserve_file_list):
        # Specifically remove any preserved files from the file system
        # after copying from the remote system
        # They will be restored from the original
        if preserve_file_list:
            for fname in preserve_file_list:
                # remove the local version of the file
                try:
                    os_remove('{}{}'.format(root_dir, fname))
                except Exception:
                    pass

    # #############################################################
    # install
    # #############################################################
    def expy_install(self):
        log.debug(sys.argv)
        src_dir = dirname(__file__)
        src = '{}/{}'.format(src_dir, self.args.install)
        for root_dir in [XDB.ROOT, XDB.ALT_ROOT]:
            dst = '{}{}/{}'.format(
                root_dir,
                src_dir,
                self.args.install)
            log.debug('src={} dst={}'.format(src, dst))
            self.system_call('mount -o remount,rw {}exos'.format(root_dir))
            log.debug('copying src={} dst={}'.format(src, dst))
            try:
                copyfile(src, dst)
            except Exception:
                pass
            self.system_call('mount -o remount,ro {}exos'.format(root_dir))

    # #############################################################
    # Config file fixup
    # #############################################################
    #
    # make any local adjustments to the config file
    # fixup action to delete a named XML node
    def delete_node(self, parentobj, obj):
        parentobj.remove(obj)

    def config_line_fixup(self, parentobj, obj):
        # add trailing blank hack for EXOS
        obj.set('xos', obj.get('version'))
        return obj.text

    # recursive function to walk the XML tree
    def walk_tree(self, parentobj, obj, no_fixup, lvl):
        fixup_map = {
            'card_info': self.delete_node,
            'cfgTechSupport': self.delete_node,
            'xos-configuration': self.config_line_fixup,
            }

        # if the tag has a matching function, perform the fixup
        func = fixup_map.get(obj.tag)
        if func:
            # fixup the field value
            obj.text = func(parentobj, obj)

        for o in list(obj):
            self.walk_tree(obj, o, no_fixup, lvl + 1)

    def cfg_file_fixup(self, cfg_file_name):
        log.debug(cfg_file_name)
        if cfg_file_name is None:
            return
        # strip off trailing NULL
        cfg_path = '/config/{}.cfg'.format(cfg_file_name.rstrip('\0'))
        log.debug('cfg file name {}'.format(cfg_path))

        try:
            with open(cfg_path, 'r') as fd_in:
                # Read the XML into a memory file, it is needed later for XML declarations
                fd_mem = StringIO.StringIO(fd_in.read())
        except Exception as e:
            log.debug(e)
            return

        # parse the XML input
        try:
            tree = ElementTree(file=fd_mem)
        except:
            print '\n**** cfg {} saved in /tmp ***\n'.format(cfg_path)
            copyfile(cfg_path, '/tmp/{}'.format(basename(cfg_path)))
            raise

        # walk the tree looking for elements to convert for stacking
        self.walk_tree(None, tree.getroot(), False, 0)

        # reset to the beginning of the input file to pick up XML declarations
        fd_mem.seek(0, 0)

        with open(cfg_path, 'w') as fd_out:
            # etree does not handle XML declarations, so we have to copy them from the input file
            for line in fd_mem.readlines():
                if line.startswith('<?'):
                    fd_out.write(line)
                    continue
                break
            # output the rest of the XML tree
            tree.write(fd_out, xml_declaration=True)
            # output ending newline to make xos happy
            fd_out.write('\n')
            fd_mem.close()

    # #############################################################
    # after stack master clone
    # #############################################################
    #
    # Once the stack master has been cloned, we need to sync the slots
    # and re-run stacking easy-setup
    #
    def post_stack_clone(self):
        if self.is_stack_master() is False:
            return
        msg = ['CLONING will continue to synchronize the remaining stack members',
               'after the stack reboots',
               ]
        self.display_box(msg, border='+')
        cmds = [
            "run script shell.py /bin/echo '*********************' 1>&2",
            "run script shell.py /bin/echo 'CLONING STACK MEMBERS' 1>&2",
            "run script shell.py /bin/echo '*********************' 1>&2",
            "config cli script timeout 6000",
            #"enable led locator timeout none slot all",
            "configure stacking slot 2 master-capability on",
            "run script {} slot all -f".format(XDB.PROCESS_NAME_PY),
            #"disable led locator slot all",
            "rm /usr/local/cfg/autoexec.xsf",
            "run script shell.py /bin/echo '****************' 1>&2",
            "run script shell.py /bin/echo 'CLONING COMPLETE' 1>&2",
            "run script shell.py /bin/echo '****************' 1>&2",
            ]
        with open('/config/autoexec.xsf', 'w') as fd:
            for cmd in cmds:
                print >> fd, cmd


# **********************************************************************
# This class is invoked in the expy context via the EXOS CLI: create process
# **********************************************************************
class CloneClientExpy(CloneBaseExpy):
    # This class contains the functionality for the clone client in all
    # modes:
    #   standalone to standalone client
    #   standalone to stacking client
    #   slot in a chassis client
    # In each one of these modes, the client is driven by the command line
    # options on the command line in the common get_params() function.
    # E.g. even though a master may be a stack, unless a slot number (-s)
    # option is provided on the command line.

    # ******************************
    # constants used in this classs
    # ******************************
    FILENAME = '/scratch/clone.json'

    # The logic is driven by a state machine.
    # Each state controls the transfer of different information from the
    # clone master switch
    class stateTrackingDB(object):
        STATE = 'state'
        DEFAULT = {STATE: 0}

        # cloning states
        START = 0
        BOOT_CFG = 1
        PROC = 2
        NVRAM = 3
        STACKING = 4
        ALL_PARTITIONS = 5
        LINUX_REBOOT = 6
        CFG_FIXUP = 7
    STATE = stateTrackingDB()

    def __init__(self):
        super(CloneClientExpy, self).__init__()
        self.clone = None
        self.state_dict = None  # keeps track of the different cloning states
        self.state = None  # current working cloning state
        self.slot = None
        self.stackingShowNode_list = None
        self.card_info_list = None  # remote system card_info
        self.rmt_dm_sysCommon = None
        self.lcl_dm_sysCommon = None
        self.nvram_dict = None
        self.block_root = False

    def __call__(self):
        # parse the command line options for the client
        self.args = self.get_params()

        # Get system information for both remote and local switches
        cmd = 'debug cfgmgr show one dm.sysCommon'
        self.rmt_dm_sysCommon = self.jsonrpc_remote_cli(cmd)[0]
        reply = self.exos_clicmd(cmd)
        try:
            self.lcl_dm_sysCommon = json_loads(reply).get('data')[0]
        except Exception as msg:
            print 'Could not determine local boot partition', msg
            print 'Cloning NOT DONE'
            return

        # check to see if the flash has enough room for this cloning method
        if self.check_flash_size() is False:
            self.display_box([
                'This switch DOES NOT support the cloning operation',
                'Cloning NOT DONE'],
                border='X')
            return

        # are the master and this switch compatible for cloning
        if self.are_systems_compatible() is False:
            self.display_box([
                'The master is NOT COMPATIBLE with this switch',
                'Cloning NOT DONE'],
                border='X')
            return

        # both switches must have either block-based root filesystems or not
        if self.are_root_fs_compatible() is False:
            self.display_box([
                'The master and this switch have different root file system locations',
                'Cloning NOT DONE'],
                border='X')
            return

        # does the master and this switch have matching stacking modes
        if self.stacking_modes_are_aligned() is False:
            self.display_box([
                'The master and this switch have different stacking modes',
                'Cloning NOT DONE'],
                border='X')
            return

        # re-nice the server to enable clients to clone quickly
        cmd = 'renice -10 {}'.format(getpid())
        self.system_call(cmd)

        self.set_log_level()
        log.debug('Starting')

        # if the client is running on an existing slot in a stack, display a message
        # in case the console is connected
        if self.is_stacking_enabled():
            print 'Cloning stack master. DO NOT REBOOT OR POWER CYCLE this switch'

            # if cloning a stacking master from another stack, store the slots present.
            # After the master is cloned and reboots, it will look for this file
            # to sync the slots to the master
            if self.is_stack_master():
                clone_slots_dict[SLOTLIST] = ExosSync.compatible_stacking_slots(self.get_slot_list())
                with open(CLONE_STK_SLOTS_FILE, 'w') as fd:
                    json_dump(clone_slots_dict, fd)

        self.slot = self.get_my_slot()

        # perform the CM startup sequence to register as a proper process with EPM
        self.cm_startup()

        # Here the client state machine order is constructed.
        # Each state is called in the order added to the list
        state_order = []
        state_order.append(CloneClientExpy.STATE.START)
        state_order.append(CloneClientExpy.STATE.NVRAM)
        # cloning from a standalone to a stacking slot requires that
        # the client collects additional stacking information
        if self.args.stacking_slot is not None:
            state_order.append(CloneClientExpy.STATE.STACKING)
        state_order.append(CloneClientExpy.STATE.ALL_PARTITIONS)
        state_order.append(CloneClientExpy.STATE.PROC)
        state_order.append(CloneClientExpy.STATE.CFG_FIXUP)

        # the last thing before reboot is to collect all of the
        # flash partitions from the master
        state_order.append(CloneClientExpy.STATE.LINUX_REBOOT)

        # this translation table maps the state into a function to call
        state_func = {
            CloneClientExpy.STATE.START:        self.client_start,
            CloneClientExpy.STATE.ALL_PARTITIONS: self.client_all_partitions,
            CloneClientExpy.STATE.NVRAM:        self.client_nvram,
            CloneClientExpy.STATE.CFG_FIXUP:    self.client_config_file_fixup,
            CloneClientExpy.STATE.STACKING:     self.client_stacking,
            CloneClientExpy.STATE.PROC:         self.client_proc_files,
            CloneClientExpy.STATE.LINUX_REBOOT: self.client_linux_reboot,
            }

        for state in state_order:
            # we store the state information in a file in case
            # the process gets interrupted
            self.client_write_state(state)
            self.client_read_state()  # get the cloning state control file
            self.state_dict[CloneClientExpy.STATE.STATE] = state

            # call the function for the state
            func = state_func.get(state)
            if func:
                rslt = func()
                if self.sock is not None:
                    self.sock.close()
                    self.sock = None

                # if the called function returns True, exit the loop
                # E.g. we are rebooting to no need to start the next
                # state.
                if rslt is True:
                    break
                else:
                    continue
            else:
                log.error('PROGRAM ERROR: unknown client function for state {}'.format(state))
                break

    def client_start(self):
        log.debug('Start cloning: sys.argv={}'.format(sys.argv))

        # start displaying progress dots to keep the user entertained
        # these do not actually represent the progress of the cloning
        # operation. They are just displayed to let the user know things
        # are still running
        #if self.is_stack_master():
        #    self.exos_clicmd('enable led locator timeout none slot all')
        #else:
        #    self.exos_clicmd('enable led locator timeout none slot {}'.format(self.slot))
        self.start_progress_dots(1)

        # collect the card_info objects from the remote system
        # on a stack, there will be one entry for every possible slot.
        # on a standalone master, there will only be one entry
        cmd = 'debug cfgmgr show next dm.card_info slot=None'
        self.card_info_list = self.jsonrpc_remote_cli(cmd)
        if self.card_info_list is None:
            print 'Cannot get boot image or boot configuration from remote system'
            return
        try:
            # the last entry is EXOS noise
            del self.card_info_list[-1]
        except Exception:
            pass

        # turn master capability off on other nodes in the stack
        # while cloning is in progress
        if self.is_stacking_enabled() and self.is_stack_master():
            cmd = []
            for slot in xrange(1, 9):
                if str(slot) == self.slot:
                    continue
                cmd.append('configure stacking slot {} master-capability off'.format(slot))
                cmd.append('reboot slot {}'.format(slot))
            self.exos_clicmd(cmd)

    def client_all_partitions(self):
        log.debug('Called')

        # memory override during cloning
        # the tar operation needs more than EXOS has configured by default
        mem_pct = self.process_group_limit()
        if mem_pct is not None:
            cmd = 'configure process group other memory-limit {}'.format(
                max(mem_pct + 5, 30))
            self.exos_clicmd(cmd)

        # if the boot partitions are swapped
        if self.rmt_dm_sysCommon.get('extremeImageBooted') == self.lcl_dm_sysCommon.get('extremeImageBooted'):
            rmt_root = XDB.ROOT
            rmt_alt = XDB.ALT_ROOT
        else:
            rmt_root = XDB.ALT_ROOT
            rmt_alt = XDB.ROOT

        # Transfer the /conf partition
        # Transfer the inactive partition to /alt first
        # Then transfer the / partitions leaving them intact for as long as possible

        # ************************************************************
        # clone the / config
        # ************************************************************
        if self.args.exos_only is False:
            self.client_xfer_files_from_master(
                    XDB.ROOT,
                    XDB.ROOT,
                    'config',
                    msg='\nTransferring /usr/local/cfg directory')
        else:
            # xos0069537
            self.client_xfer_files_from_master(
                    XDB.ROOT,
                    XDB.ROOT,
                    'config/.history',
                    msg='\nTransferring EXOS version information')

        # ************************************************************
        # make each partition in the list read/write so we can update it
        # ************************************************************
        print '\nEnabling partition write'
        # Note Well: /root is a bound mountpoint - don't try to remount it
        partitions = ['boot', 'exos']
        while self.make_partition_read_write(XDB.ROOT, partitions) is False:
            # re-run this state if something went wrong
            continue
        if self.block_root is True:
            partitions.append('root')
        while self.make_partition_read_write(XDB.ALT_ROOT, partitions) is False:
            # re-run this state if something went wrong
            continue

        # ************************************************************
        # clone the /alt partitions
        # ************************************************************
        print '\nTransferring inactive EXOS partition',
        self.client_xfer_files_from_master(
                rmt_alt,
                XDB.ALT_ROOT,
                'boot',
                preserve_file_list=['boot/system.cfg'],
                exclude='grub',
                rmsubdirs=False if self.is_onie_device() else True)

        # ONIE support
        if self.is_onie_device():
            try:
                os_remove('{}boot/grub/grubenv'.format(XDB.ALT_ROOT))
            except Exception:
                pass
            # If it exists
            # copy the grubenv which contains the exos versions
            self.client_xfer_files_from_master(
                    rmt_alt,
                    XDB.ALT_ROOT,
                    'boot/grub/grubenv',
                    rmsubdirs=False)

        self.client_xfer_files_from_master(
                rmt_alt,
                XDB.ALT_ROOT,
                'exos')

        if self.block_root:
            print '\nTransferring inactive ROOT partition',
            self.client_xfer_cpio_from_master(
                    rmt_alt,
                    XDB.ALT_ROOT,
                    'root')

        # ************************************************************
        # clone the / partitions
        # ************************************************************
        print '\nTransferring active EXOS partition',

        # we stop the CLI master here to avoid any cli commands from accessing
        # the file system which is about to be removed
        self.stop_hal()

        self.client_xfer_files_from_master(
                rmt_root,
                XDB.ROOT,
                'boot',
                preserve_file_list=['boot/system.cfg'],
                exclude='grub',
                rmsubdirs=False if self.is_onie_device() else True)

        # ONIE support
        if self.is_onie_device():
            try:
                os_remove('{}boot/grub/grubenv'.format(XDB.ROOT))
            except Exception:
                pass
            # If it exists
            # copy the grubenv which contains the exos versions
            self.client_xfer_files_from_master(
                    rmt_root,
                    XDB.ROOT,
                    'boot/grub/grubenv',
                    rmsubdirs=False)

        self.client_xfer_files_from_master(
                rmt_root,
                XDB.ROOT,
                'exos')

        if self.block_root:
            # Special Handling for the Active Root
            # We can't just overwrite the root out from under the running OS.
            # We stash the active root in a cpio archive.
            # During early boot, before we switch roots, we'll replace the
            # active root partition contents with the stashed archive.
            print '\nTransferring active ROOT partition'
            cmd = 'cat {}root/etc/extreme/.valid_root__'.format(rmt_root)
            rmt_root_hash = self.jsonrpc_remote_shell(cmd)[0]
            log.debug('Transferring active ROOT partition ({} from {})'.format(rmt_root_hash, cmd))
            lcl_archive = XDB.ROOT_ARCHIVE.format(hash=rmt_root_hash)
            self.client_xfer_archive_from_master(rmt_root, 'root', lcl_archive)
            log.debug('Active ROOT Archive: {}'.format(lcl_archive))
            self.stage_active_root(rmt_root_hash)

        return

    def client_xfer_archive_from_master(
            self,
            rmt_root_dir,
            partition,
            lcl_archive,
            msg=None):
        if msg:
            print msg

        # The directory to archive up
        rqst_dict = {
            XDB.RQST.ROOT: rmt_root_dir,
            XDB.RQST.DIRS: [partition],
            XDB.RQST.DM_SYSTEM: self.get_dm_system()
            }

        # Clean up old archive
        if exists(lcl_archive):
            os_remove(lcl_archive)

        # Create the staging dir if needed
        if not exists(dirname(lcl_archive)):
            makedirs(dirname(lcl_archive))

        # Keep trying until success
        while True:
            try:
                self.cpio_archive_from_master(rqst_dict, lcl_archive)
                break
            except Exception as e:
                print '\nTransfer from master interrupted:', e
                print 'Verify network connectivity and master is running'
                print 'Retrying data transfer from Master'
        return

    def client_xfer_cpio_from_master(
            self,
            rmt_root_dir,
            lcl_root_dir,
            partition,
            msg=None,
            exclude=None,
            rmsubdirs=True):
        if msg:
            print msg

        # The directory to archive up
        rqst_dict = {
            XDB.RQST.ROOT: rmt_root_dir,
            XDB.RQST.DIRS: [partition],
            XDB.RQST.DM_SYSTEM: self.get_dm_system()
            }

        if rmsubdirs:
            self.system_call('rm -rf {}{}/*'.format(lcl_root_dir, partition))

        # Keep trying until success
        while True:
            try:
                self.cpio_data_from_master(rqst_dict, lcl_root_dir, partition)
                break
            except Exception as e:
                print '\nTransfer from master interrupted:', e
                print 'Verify network connectivity and master is running'
                print 'Retrying data transfer from Master'
        return

    def client_xfer_files_from_master(
            self,
            rmt_root_dir,
            lcl_root_dir,
            partition,
            msg=None,
            preserve_file_list=None,
            exclude=None,
            rmsubdirs=True):
        if msg:
            print msg,
        # control structure to manage which partitions get cloned
        rqst_dict = {
            XDB.RQST.ROOT: rmt_root_dir,
            XDB.RQST.DIRS: [partition],
            XDB.RQST.EXCLUDE: exclude,
            XDB.RQST.DM_SYSTEM: self.get_dm_system()
            }

        # some files have switch specific local significance and need to be preserved
        keep_file_dict = self.read_preserve_file(lcl_root_dir, preserve_file_list)

        if rmsubdirs:
            self.system_call('rm -rf {}{}/*'.format(lcl_root_dir, partition))

        # this is the function that does the work
        # the directories are tarred from the master and
        # un-tarred to this switched
        while True:
            try:
                self.tar_data_from_master(rqst_dict, lcl_root_dir)
                break
            except Exception as e:
                print '\nTransfer from master interrupted:', e
                print 'Verify network connectivity and master is running'
                print 'Retrying data transfer from Master'

        # remove any preserved files that may have been copied
        self.remove_preserve_file(lcl_root_dir, preserve_file_list)

        # restore any local files that needed to be preserved
        self.write_preserve_file(lcl_root_dir, keep_file_dict)

        return

    def client_proc_files(self):
        # copy individual files from the master
        # most of the time these files in the /proc file system
        log.debug('Called')

        for f in [
                # ('/proc/extr/nvram/fs_access', '/proc/extr/nvram/fs_access'),
                ('/proc/extr/nvram/bootsel', '/proc/extr/nvram/bootsel'),
                ('/proc/extr/nvram/cmdline', '/proc/extr/nvram/cmdline'),
                # ('/proc/extr/nvram/config', '/proc/extr/nvram/config'),
                # ('/proc/extr/nvram/configname', '/proc/extr/nvram/configname'),
                ('/proc/extr/nvram/fsu', '/proc/extr/nvram/fsu'),
                ('/proc/extr/nvram/fsp', '/proc/extr/nvram/fsp')
                ]:
            self.cat_file_from_master(rmt_file=f[0], lcl_file=f[1])

    def client_nvram(self):
        # collect the nvram image from both the remote and local system
        # The client needs to process specific TLVs and not copy the
        # the entire nvram
        log.debug('Called')
        if len(self.card_info_list) > 1:
            # remote system is a stack, find the master
            for card_info in self.card_info_list:
                if card_info.get('node_state_str') == 'MASTER':
                    break
        else:
            card_info = self.card_info_list[0]

        self.jsonrpc_send(XDB.CAT, NVRAM_FILE)
        nvram = NvramSync()
        fd = open(NVRAM_FILE, 'r+b')
        self.nvram_dict = nvram.clone_common_objects(
            self.sock,
            fd,
            exos_only=self.args.exos_only)
        fd.close()

        # clone specific EEPROM objects
        self.jsonrpc_send(XDB.CAT, EEPROM_FILE)
        nvram = NvramSync()
        fd = open(EEPROM_FILE, 'r+b')
        nvram.clone_eeprom_objects(
            self.sock,
            fd,
            exos_only=self.args.exos_only)
        fd.close()

    def client_config_file_fixup(self):
        cfg_file_name = self.nvram_dict.get(NvramSync.NV.CM_CONFIG_FILENAME_INFO)
        self.cfg_file_fixup(cfg_file_name)

        # if we are cloning a stack, schedule the post clone work after reboot
        if self.is_stacking_enabled():
            self.post_stack_clone()

    def client_stacking(self):
        # collect the stacking objects from the remote system
        cmd = 'debug cfgmgr show next hal.stackingShowNode'
        self.stackingShowNode_list = self.jsonrpc_remote_cli(cmd)

        # if cloning a specific stacking slot, check if the remote system is a stack
        card_info = self.card_info_list[0]
        if card_info.get('platformHasSlots') != '1':
            print 'Master swtich is not a stack. Cannot clone slot {}'.format(
                self.args.stacking_slot[0])

            # tell EXOS to delete this process
            self.process_cleanup()

            # wait here to give EXOS a chance to delete this process
            sleep(100)
            return

        if self.args.stacking_slot[0] == 0:
            self.client_stacking_new_slot()
        else:
            self.client_stacking_existing_slot()

    def client_stacking_new_slot(self, requested_slot=None):
        # find an available slot
        if requested_slot:
            available_slot = requested_slot
        else:
            for card_info in self.card_info_list:
                # look for card_state = '1' i.e. empty
                if card_info.get('card_state') == '1':
                    available_slot = card_info.get('slot')
                    print 'Using first available slot {}'.format(available_slot)
                    break

            if available_slot is None:
                print 'Master stack does not have any available slots'

                # tell EXOS to delete this process
                self.process_cleanup()
                # wait here to give EXOS a chance to delete this process
                sleep(100)
                return

        # look for the stacking master slot, then use that information with the
        # user provided slot number
        for card_info in self.card_info_list:
            if card_info.get('node_state_str') == 'MASTER':
                log.debug('Found remote stack master on slot {}'.format(
                    card_info.get('slot')))
                break
        else:
            print 'Cannot find stacking master slot and desired slot {} does not exist'.format(
                self.args.stacking_slot[0])
            # tell EXOS to delete this process
            self.process_cleanup()
            # wait here to give EXOS a chance to delete this process
            sleep(100)
            return

        # find node information for the master slot
        for stackingShowNode in self.stackingShowNode_list:
            if stackingShowNode.get('cfg_slot') == card_info.get('slot'):
                break
        else:
            print 'Cannot find stacking node information for slot {}'.format(
                card_info.get('slot'))
            # tell EXOS to delete this process
            self.process_cleanup()
            # wait here to give EXOS a chance to delete this process
            sleep(100)
            return

        # use the empty slot number we found before
        stackingShowNode['cfg_slot'] = available_slot

        # set the stacking master capability
        if self.args.stacking_master is True:
            print 'Switch will be stacking master capable'
            stackingShowNode['cfg_mstr_flg'] = '1'
        else:
            stackingShowNode['cfg_mstr_flg'] = '0'

        self.client_stacking_config(stackingShowNode)
        return

    def client_stacking_existing_slot(self):
        # a specific slot was used on the command line
        # find the slot on the master stack

        # look for a matching slot
        for stackingShowNode in self.stackingShowNode_list:
            if stackingShowNode.get('slot') == str(self.args.stacking_slot[0]):
                self.client_stacking_config(stackingShowNode)
                return

        print 'Cannot find stacking node information for slot {}'.format(
            self.args.stacking_slot[0])
        print 'Adding switch as a new stack member slot {}'.format(
            self.args.stacking_slot[0])
        return self.client_stacking_new_slot(requested_slot=self.args.stacking_slot[0])

    def client_stacking_config(self, stackingShowNode):
        # stackingShowNode contains the information from the reference stack for this switch
        self.get_dm_system()
        myMac = self.dm_dict.get('macAddr')
        stkMac_parts = stackingShowNode.get('stkMAC').split(':')
        if stkMac_parts[0] == '02':
            # clear local admin bit
            stkMac_parts[0] = '00'
        stkMac = ':'.join(stkMac_parts)
        cmd_list = [
                'enable stacking node-address {}'.format(myMac),
                'configure stacking node-address {} master-capability {}'.format(
                    myMac,
                    'on' if stackingShowNode.get('cfg_mstr_flg') == '1' else 'off'),
                'configure stacking node-address {} slot-number {}'.format(
                    myMac,
                    stackingShowNode.get('cfg_slot')),
                'configure stacking node-address {} mac-address'.format(stkMac),
                ]
        for cmd in cmd_list:
            log.debug(cmd)
        self.exos_clicmd(cmd_list)

    def client_linux_reboot(self):
        # last thing the client does is reboot using the linux boot
        # the client cannot use the EXOS reboot command because it
        # would attempt to save the config on a file system that was
        # just cloned from the mster
        self.client_remove_state_file()
        self.stop_progress_dots()
        if self.args.exos_only is True:
            print 'Rebooting to master switch EXOS image'
        else:
            print 'Rebooting to master switch configuration'
            print 'You may need to adjust any IP addresses',
            print 'that may have been copied from the master switch'
        if not self.is_stacking_enabled():
            self.display_box(['Cloning COMPLETE'], border='*')
        print 'Rebooting ...'
        # if cloning a stack, reboot any other slot
        self.system_call('sync;sync;reboot -f')

    def connect_to_master(self):
        # Create a socket (SOCK_STREAM means a TCP socket)
        environ["EXOS_VR_ID"] = str(self.vr)
        sock = socket(AF_INET, SOCK_STREAM)

        # the socket VR from the command line must be set
        sock.setsockopt(SOL_SOCKET, 37, self.vr)
        sock.settimeout(XDB.CLIENT_SOCKET_TIMEOUT)
        addr = (self.args.ipaddress, XDB.SOCKET_PORT)
        log.debug('Connecting to {}'.format(addr))

        display_connect_message = False
        for retry in xrange(50):
            try:
                sock.connect(addr)
                break
            except Exception as msg:
                print '\nCannot connect to {}: {}\nEnsure client IP address is configured and master is running\n'.format(
                        self.args.ipaddress, msg)
                display_connect_message = True
                sleep(3)
        else:
            log.error('Socket cannot connect with {}'.format(addr))
            raise
        if display_connect_message:
            print '\nConnected to {}\n'.format(self.args.ipaddress)
        return sock, addr

    def are_root_fs_compatible(self):

        # Both systems must be block-root (EXOS 30.3 or later)
        # -- OR --
        # Both systems must not be block-root
        lcl_block_root, lcl_both_same = self.is_block_root(self.lcl_dm_sysCommon)
        rmt_block_root, rmt_both_same = self.is_block_root(self.rmt_dm_sysCommon)
        if lcl_both_same is not True or rmt_both_same is not True:
            log.debug('Incompatible file systems - local: {}/{} remote: {}/{}'.format(lcl_block_root, lcl_both_same, rmt_block_root, rmt_both_same))
            return False
        elif lcl_block_root == rmt_block_root:
            log.debug('Compatible file systems - local: {}/{} remote: {}/{}'.format(lcl_block_root, lcl_both_same, rmt_block_root, rmt_both_same))
            self.block_root = lcl_block_root
            return True
        else:
            log.debug('Incompatible file systems - local: {}/{} remote: {}/{}'.format(lcl_block_root, lcl_both_same, rmt_block_root, rmt_both_same))
            return False

    def are_systems_compatible(self):
        # check if remote system is compatible with this one
        # Look in /proc/cpuinfo on both systems for specific
        # infomation that must match
        with open('/proc/cpuinfo', 'r') as fd:
            lcl_cpuinfo = fd.readlines()
        rmt_cpuinfo = self.jsonrpc_remote_shell('cat /proc/cpuinfo')

        # search for key words that are unique to a cpu type
        # i.e. the keyword only exist on one cpu type and not the other
        # e.g. MIPS CPUs have the keyword 'isa' while intel has 'flags'
        for cpu_key in ['isa', 'flags']:
            for cpu_line in lcl_cpuinfo:
                if cpu_line.startswith(cpu_key):
                    # found matching keyword, check remote system
                    break
            else:
                # none of the lines matched
                continue

            # found a matching keyword in the local system
            # does the remote system have the same keyword?
            for cpu_line in rmt_cpuinfo:
                if cpu_line.startswith(cpu_key):
                    return True

            # the remote system does not have a matching keyword
            return False

        # Both systems must be running block-root (EXOS 30.3 or later)
        # -- OR --
        # Both systems must not be running block-root
        lcl_block_root, lcl_both_same = self.is_block_root(self.lcl_dm_sysCommon)
        rmt_block_root, rmt_both_same = self.is_block_root(self.rmt_dm_sysCommon)
        if lcl_both_same is not True or rmt_both_same is not True:
            return False
        if lcl_block_root == rmt_block_root:
            self.block_root = lcl_block_root
            return True

        # local system doesn't match any of the known keywords
        return False

    def stacking_modes_are_aligned(self):
        # if only the exos images are being cloned, it doesn't matter
        # if the stacking modes aligh
        if self.args.exos_only:
            return True

        # compare the stack mode of the master and this switch
        # return False if they are not the same
        rmt_stack_mode_list = self.jsonrpc_remote_shell('echo $EXOS_STACK_MODE')
        rmt_stack_str = ''.join(rmt_stack_mode_list).strip()
        is_rmt_stack = True if rmt_stack_str == '1' else False

        lcl_stack_str = getenv('EXOS_STACK_MODE')
        is_lcl_stack = True if lcl_stack_str == '1' else False

        # is local standalone switch being cloned for stack membership
        if is_lcl_stack is False and is_rmt_stack is True:
            # were either of the command line options entered to indicate
            # new stack membership
            if self.args.stacking_slot or self.args.stacking_master:
                return True

        # are stacking roles aligned
        if is_lcl_stack == is_rmt_stack:
            return True

        return False

    def check_flash_size(self):
        # check if the flash size is big enough to support cloning
        # returns: True if flash can support cloning
        #          False if flash size cannot support cloning
        #
        # NOTE WELL!! - It is important that this function checks for
        #               /dev/mmcblk0 BEFORE /dev/sda in order to support
        #               machines with both eMMC and SSD such as the X465.
        for disk_dev in ['', '/dev/mmcblk0', '/dev/sda', '/dev/hda']:
            try:
                reply = subprocess_check_output(
                        "lsblk -bnr -o type,size {} | grep '^disk'".format(disk_dev),
                        shell=True)
                # found the disk size header
                log.debug(reply)
                break
            except subprocess_CalledProcessError as e:
                # grep could not find a match
                log.debug('{} {}'.format(disk_dev, e))
                continue
        else:
            # could not find a matching fdisk reply, assume we are good
            return True

        # examine all numbers to see if there is at least one that is big enough
        # that should be the size in bytes
        for r in reply.split():
            if r.isdigit():
                if int(r) > (2*1024*1024*1024):
                    return True
        return False

    def make_partition_read_write(self, root_dir=XDB.ROOT, dir_list=[]):
        # change the partitions to R/W
        for d in dir_list:
            cmd = [
                'mount -o remount,rw {}{}'.format(root_dir, d)
                ]
            self.system_call(cmd)
        return True

    def cmd_output_from_master(self, op, params=None, cmd=None):
        # send the request to the master
        self.jsonrpc_send(op, params)
        start_time = time()
        log.debug(cmd)
        try:
            subprocess_check_call(cmd, stdin=self.sock.fileno(), shell=True)
        except subprocess_CalledProcessError as e:
            log.debug('{} command failed'.format(e.cmd))
            raise

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))

    def cpio_archive_from_master(self, params=None, lcl_archive=None):
        # Local command to store cpio archive
        cmd = 'cat > {} 2>/dev/null'.format(lcl_archive)
        self.cmd_output_from_master(XDB.CPIO, params, cmd)

    def cpio_data_from_master(self, params=None, lcl_root_dir=None, partition=None):
        # local command to extract files from the cpio archive
        cmd = 'cpio -idu -R root:root 2>/dev/null'
        chdir('{}{}'.format(lcl_root_dir, partition))
        self.cmd_output_from_master(XDB.CPIO, params, cmd)
        chdir(self.cwd)

    def tar_data_from_master(self, params=None, lcl_root_dir=None):
        # local tar command to extract the remote system files back
        # into the paritions
        cmd = 'tar -xf - -C {}'.format(lcl_root_dir)
        self.cmd_output_from_master(XDB.TAR, params, cmd)

    def cat_file_from_master(self, rmt_file=None, lcl_file=None):
        # directly import a file from the remote system and write it
        # to the local system

        # look for special file names
        for reserved_name in ['/proc', '/dev']:
            # local file name is special?
            if lcl_file.startswith(reserved_name):
                # does special file name exist on the local system?
                if not isfile(lcl_file):
                    # file name does not exist on this system.
                    # do not try to copy it from the master
                    return True

        # params is a single string
        self.jsonrpc_send(XDB.CAT, rmt_file)

        cmd = 'cat > {}'.format(lcl_file)
        log.debug(cmd)

        if not isdir(dirname(lcl_file)):
            try:
                makedirs(dirname(lcl_file))
            except Exception as e:
                log.debug(e)
        try:
            subprocess_check_call(cmd, stdin=self.sock.fileno(), shell=True)
            print 'Copying remote file {} to {}'.format(rmt_file, lcl_file)
        except subprocess_CalledProcessError as e:
            log.debug('{} command failed'.format(e.cmd))
            return False

        return True

    # ************************************************************
    # Client State machine state DB read/write routines
    # ************************************************************
    def client_write_state(self, state):
        log.debug('New state {}'.format(state))
        if self.state_dict is None:
            log.debug('No state structure')
            self.client_read_state()

        self.state_dict[CloneClientExpy.STATE.STATE] = state
        log.debug(self.state_dict)
        with open(CloneClientExpy.FILENAME, 'w') as fd:
            json_dump(self.state_dict, fd)

    def client_read_state(self):
        # display these messages when the beginning each state
        state_status_msg = {
            CloneClientExpy.STATE.START:
                'Starting cloning process',
            CloneClientExpy.STATE.BOOT_CFG:
                'Getting boot partition and configuration file name',
            CloneClientExpy.STATE.NVRAM:
                'Transfering NVRAM information from master switch',
            CloneClientExpy.STATE.CFG_FIXUP:
                'Config file fixup for this switch',
            CloneClientExpy.STATE.STACKING:
                'Transfering stacking information from master switch',
            CloneClientExpy.STATE.PROC:
                'Transfering control information from master switch',
            CloneClientExpy.STATE.ALL_PARTITIONS:
                'Transfering EXOS partitions and configuration',
            }

        try:
            with open(CloneClientExpy.FILENAME, 'r') as fd:
                self.state_dict = json_load(fd)
            # remove the file to avoid reboot loops if something goes wrong
            self.client_remove_state_file()
        except Exception:
            self.state_dict = CloneClientExpy.STATE.DEFAULT

        log.debug(json_dumps(self.state_dict, indent=2, sort_keys=True))

        print '\n', state_status_msg.get(
            self.state_dict.get(CloneClientExpy.STATE.STATE), '')

    def client_remove_state_file(self):
        try:
            os_remove(CloneClientExpy.FILENAME)
        except Exception:
            pass


# **********************************************************************
# This class is invoked in the expy context via the EXOS CLI: create process
# **********************************************************************
class CloneUsbExpy(CloneBaseExpy):
    def __init__(self):
        super(CloneUsbExpy, self).__init__()
        self.nvram_dict = {}
        self.slot = None
        self.rmt_environ = {}
        self.lcl_dm_sysCommon = None
        self.usb_roots = [['/root',     'act_root'],
                          ['/alt/root', 'alt_root'],]
        self.cwd = '/'

    def __call__(self):
        # parse the command line options for the client
        log.debug('Called')
        self.args = self.get_params()

        self.cwd = getcwd()

        # Get system information for the local switch
        cmd = 'debug cfgmgr show one dm.sysCommon'
        reply = self.exos_clicmd(cmd)
        try:
            self.lcl_dm_sysCommon = json_loads(reply).get('data')[0]
        except Exception as msg:
            print 'Could not get system information', msg
            print 'Cloning NOT DONE'
            return

        # Both systems must be block-root (EXOS 30.3 or later)
        # -- OR --
        # Both systems must not be block-root
        self.block_root, lcl_both_same = self.is_block_root(self.lcl_dm_sysCommon)
        if lcl_both_same is not True:
            self.display_box([
                'Both primary and secondary must have EXOS 30.3 or later',
                'or both must have older than 30.3',
                'Cloning NOT DONE'],
                border='X')
            self.process_cleanup()
            return

        if self.args.usb_input:
            log.debug('USB clone from file')
            self.usb_clone_from_file()
        elif self.args.usb_output:
            log.debug('USB clone to file')
            self.usb_clone_to_file()
        else:
            print 'Program error: unknow USB option'
        self.process_cleanup()

    def usb_clone_to_file(self):
        # copy nvram contents into a scratch file
        # file list. Make scrach file copies
        scratch_file_list = [
            NVRAM_FILE,
            EEPROM_FILE,
            '/proc/extr/nvram/bootsel',
            '/proc/extr/nvram/cmdline',
            '/proc/extr/nvram/fsu',
            '/proc/extr/nvram/fsp',
            '/proc/cpuinfo',
            '/proc/self/environ',
            ]
        tar_list = []
        for scr_file in scratch_file_list:
            scratch_name = '/scratch/{}'.format(basename(scr_file))
            self.usb_clone_make_scratch_copy(
                scr_file, scratch_name)
            tar_list.append(scratch_name.lstrip('/'))

        # Create CPIO archives and dictionary of the root dirs
        # The dictionary is used to map the archive to its valid root hash.
        tar_list.append(XDB.USB_ROOT_DICT.lstrip('/'))
        dict_fd = open(XDB.USB_ROOT_DICT, "w")
        for root in self.usb_roots:
            # Need a map of archive to hash
            root_hash = 'Invalid-Root-Filesystem'
            root_valid = '{}/etc/extreme/.valid_root__'.format(root[0])
            if exists(root_valid):
                with open(root_valid) as f:
                    root_hash = f.read().strip()
            else:
                continue
            dict_fd.write('{}:{}\n'.format(root[1], root_hash))

            # Create a cpio archive of the root partition
            archive = '/scratch/{}'.format(root[1])
            tar_list.append(archive.lstrip('/'))
            cmd = 'find . | cpio -oH newc > {}'.format(archive)
            log.debug(cmd)
            start_time = time()
            chdir('{}'.format(root[0]))
            self.system_call(cmd)
            chdir(self.cwd)
            log.debug('Elapse time {} seconds'.format(time() - start_time))
        dict_fd.close()

        # Version compatiblilty added in 1.2.0.1
        tar_list.append(XDB.USB_MASTER_VERSION.lstrip('/'))
        with open(XDB.USB_MASTER_VERSION, "w") as f:
            f.write('{}\n'.format(__version__))

        root_dir = '/'
        tar_list += [
            'alt/boot',
            'alt/exos',
            'boot',
            'exos',
            ]
        if self.args.exos_only is False:
            tar_list.append('config')

        cmd = 'tar -cf {} -C {} {}'.format(
            self.args.usb_output,
            root_dir,
            ' '.join(tar_list))
        log.debug(cmd)

        start_time = time()

        self.system_call(cmd)

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))

        # make a copy of myself on the USB drive
        dst = '{}/{}'.format(XDB.USB_DIR, basename(__file__))
        log.debug('copying src={} dst={}'.format(__file__, dst))
        copyfile(__file__, dst)

    def usb_clone_from_file(self):
        log.debug('Called')
        pwd = getcwd()

        # re-nice the server to enable clients to clone quickly
        cmd = 'renice -10 {}'.format(getpid())
        self.system_call(cmd)

        # filename is absolute or relative path
        # determine abolute path name
        for usb_dir in ['', XDB.USB_DIR]:
            usb_path = '{}{}'.format(usb_dir, self.args.usb_input)
            log.debug(usb_path)
            if isfile(usb_path):
                log.debug('found {}'.format(usb_path))
                break
        else:
            print 'Cannot find file', self.args.usb_input
            return

        # sanity check, verify this is a tar file
        if ExpyTar.is_tar(usb_path) is not True:
            print 'File {} was not created by {}'.format(
                self.args.usb_input,
                XDB.PROCESS_NAME)
            return

        usb_tar = ExpyTar()
        # test if we can open the file
        try:
            usb_tar.open(usb_path, 'r')
        except Exception as msg:
            print 'Cannot open file {}. {}'.format(self.args.usb_input, msg)
            return

        # test if the USB was created from a compatible version
        if self.usb_is_master_compatible(usb_tar) is False:
            self.display_box([
                'The USB clone image was created by clone command',
                'that is NOT COMPATIBLE with this command.',
                'Cloning NOT DONE'],
                border='X')
            return

        # test if the usb clone image came from a compatible switch
        if self.usb_are_systems_compatible(usb_tar) is False:
            self.display_box([
                'The USB clone image is NOT COMPATIBLE with this switch',
                'Cloning NOT DONE'],
                border='X')
            return

        if self.usb_are_root_fs_compatible(usb_tar) is False:
            self.display_box([
                'The USB clone image and this switch have different root file system locations',
                'Cloning NOT DONE'],
                border='X')
            return

        if self.usb_stacking_modes_are_aligned(usb_tar) is False:
            self.display_box([
                'The USB clone image and this switch have different stacking modes',
                'Cloning NOT DONE'],
                border='X')
            return

        root_dict = {}
        if self.block_root is True:
            # Import the root dictionary from the tar file
            try:
                fd = usb_tar.open_file(XDB.USB_ROOT_DICT.strip('/'))
                for line in fd:
                    key,val = line.split(':')
                    root_dict[key] = val.strip()
                fd.close()
            except:
                pass

            if len(root_dict) < 2:
                self.display_box([
                    'The USB clone image does not contain a root dictionary.',
                    'Cloning NOT DONE'],
                    border='X')
                return

        # if we are cloning a stack, start blinking all of the lights
        #if self.is_stacking_enabled():
        #    self.exos_clicmd('enable led locator timeout none slot all')

        # memory override during cloning
        mem_pct = self.process_group_limit()
        if mem_pct is not None:
            cmd = 'configure process group other memory-limit 30'
            self.exos_clicmd(cmd)

        # turn master capability off on other nodes in the stack
        # while cloning is in progress
        self.slot = self.get_my_slot()
        if self.is_stacking_enabled():
            # if cloning a stacking master from USB, store the slots present.
            # After the master is cloned and reboots, it will look for this file
            # to sync the slots to the master
            if self.is_stack_master():
                clone_slots_dict[SLOTLIST] = ExosSync.compatible_stacking_slots(self.get_slot_list())
                with open(CLONE_STK_SLOTS_FILE, 'w') as fd:
                    json_dump(clone_slots_dict, fd)
            cmd = []
            for slot in xrange(1, 9):
                if str(slot) == self.slot:
                    continue
                cmd.append('configure stacking slot {} master-capability off'.format(slot))
                cmd.append('reboot slot {}'.format(slot))
            self.exos_clicmd(cmd)

        # update NVRAM
        print '\nTransfering NVRAM information from USB'
        self.usb_clone_from_file_nvram(usb_tar)

        # if not just EXOS, do the /config partition
        if self.args.exos_only is False:
            print '\nTransferring /usr/local/cfg directory'
            self.usb_clone_from_file_untar(usb_tar, 'config', '/')
        else:
            self.usb_clone_from_file_untar(usb_tar, 'config/.history', '/')

        if self.is_onie_device():
            boot_exclude = 'grub'
            rmsubdirs = False
            log.debug('ONIE device')
        else:
            boot_exclude = None
            rmsubdirs = True
            log.debug('not ONIE device')

        if self.usb_clone_boot_swap(usb_tar) is True:
            print '\nTransferring active EXOS partition from USB'
            # tar files have names that start with alt/
            # first the files are extracted to the /alt patitions
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/exos',
                    '/')
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/boot',
                    '/',
                    exclude=boot_exclude,
                    rmsubdirs=rmsubdirs)

            try:
                os_remove('/alt/boot/grub/grubenv')
            except Exception:
                pass
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/boot/grub/grubenv',
                    '/')

            # now copy from the /alt partition to the / paritition
            self.usb_copy_partitions(
                    '/alt/exos',
                    '/exos')
            self.usb_copy_partitions(
                    '/alt/boot',
                    '/boot',
                    exclude=boot_exclude,
                    rmsubdirs=rmsubdirs)

            print '\nTransferring inactive EXOS partition from USB'
            # lastly transfer exos, boot to /alt
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'exos',
                    '/alt/')
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'boot',
                    '/alt/',
                    exclude=boot_exclude,
                    rmsubdirs=rmsubdirs)

            if self.block_root is True:
                # transfer /root to /alt/root
                print '\nTransferring active ROOT partition from USB'
                self.usb_clone_from_file_cpio(
                        usb_tar,
                        'scratch/{}'.format(self.usb_roots[0][1]),
                        '/alt/root')

                # Copy the cpio archive of the alt_root to
                # the staging location for the active root.
                alt_root = self.usb_roots[1][1]
                root_hash = root_dict[alt_root]
                root_archive = XDB.ROOT_ARCHIVE.format(hash=root_hash)
                print '\nTransferring inactive ROOT partition from USB'
                self.usb_clone_from_file_copy(
                    usb_tar,
                    'scratch/{}'.format(alt_root),
                    root_archive)
                self.stage_active_root(root_hash)

            try:
                os_remove('/alt/boot/grub/grubenv')
            except Exception:
                pass
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'boot/grub/grubenv',
                    '/alt/')
        else:
            print '\nTransferring inactive EXOS partition from USB'
            # files are extracted to the /alt patitions
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/exos',
                    '/')
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/boot',
                    '/',
                    exclude=boot_exclude,
                    rmsubdirs=rmsubdirs)
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'alt/boot/grub/grubenv',
                    '/')

            print '\nTransferring active EXOS partition from USB'
            # files are extracted to the / patitions
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'exos',
                    '/')
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'boot',
                    '/',
                    exclude=boot_exclude,
                    rmsubdirs=rmsubdirs)

            if self.block_root is True:
                # transfer /alt/root to /alt/root
                print '\nTransferring inactive ROOT partition from USB'
                self.usb_clone_from_file_cpio(
                        usb_tar,
                        'scratch/{}'.format(self.usb_roots[1][1]),
                        '/alt/root')

                # Copy the cpio archive of the act_root to
                # the staging location for the active root.
                act_root = self.usb_roots[0][1]
                root_hash = root_dict[act_root]
                root_archive = XDB.ROOT_ARCHIVE.format(hash=root_hash)
                print '\nTransferring active ROOT partition from USB'
                self.usb_clone_from_file_copy(
                    usb_tar,
                    'scratch/{}'.format(self.usb_roots[0][1]),
                    root_archive)
                self.stage_active_root(root_hash)

            try:
                os_remove('/boot/grub/grubenv')
            except Exception:
                pass
            self.usb_clone_from_file_untar(
                    usb_tar,
                    'boot/grub/grubenv',
                    '/')

        scratch_file_list = [
            '/proc/extr/nvram/bootsel',
            '/proc/extr/nvram/cmdline',
            '/proc/extr/nvram/fsu',
            '/proc/extr/nvram/fsp',
            ]

        for f in scratch_file_list:
            log.debug(f)
            fd = open(f, 'r+b')
            in_fd = usb_tar.open_file('scratch/{}'.format(basename(f)))
            fd.write(in_fd.read())
            in_fd.close()
            fd.close()

        usb_tar.close()

        # the last thing to do is clean up the cfg file
        cfg_file_name = self.nvram_dict.get(NvramSync.NV.CM_CONFIG_FILENAME_INFO)

        print '\nConfig file fixup for this switch'
        self.cfg_file_fixup(cfg_file_name)

        # if we are cloning a stack, schedule the post clone work after reboot
        if self.is_stacking_enabled():
            log.debug('create post clone')
            self.post_stack_clone()
        else:
            print
            self.display_box(['USB Cloning COMPLETE'], border='*')

        cmd = [
                'sync',
                'sync',
                'reboot -f',
            ]
        self.system_call(cmd)
        return

    def usb_clone_from_file_nvram(self, usb_tar):
        # NVRAM requires special processing
        usb_fd = usb_tar.open_file('scratch/{}'.format(basename(NVRAM_FILE)))
        usb_fd = StringIO.StringIO(usb_fd.read())

        nvram = NvramSync()
        lcl_fd = open(NVRAM_FILE, 'r+b')
        self.nvram_dict.update(
                nvram.clone_common_objects(
                    usb_fd,
                    lcl_fd,
                    exos_only=self.args.exos_only))
        usb_fd.close()
        lcl_fd.close()

        # clone selected eeprom objects
        usb_fd = usb_tar.open_file('scratch/{}'.format(basename(EEPROM_FILE)))
        nvram = NvramSync()
        lcl_fd = open(EEPROM_FILE, 'r+b')
        self.nvram_dict.update(
                nvram.clone_eeprom_objects(
                    usb_fd,
                    lcl_fd,
                    exos_only=self.args.exos_only))
        usb_fd.close()
        lcl_fd.close()

    @staticmethod
    def usb_clone_make_scratch_copy(from_file, to_file):
        # copy dev or proc file contents into a scratch file
        with open(from_file, 'rb') as fd:
            out_fd = open(to_file, 'wb')
            out_fd.write(fd.read())
            out_fd.close()

    @staticmethod
    def usb_clone_from_file_copy(usb_tar, from_file, to_file):
        if not exists(dirname(to_file)):
            makedirs(dirname(to_file))
        fd = open(to_file, 'wb')
        in_fd = usb_tar.open_file(from_file)
        fd.write(in_fd.read())
        in_fd.close()
        fd.close()

    def usb_clone_boot_swap(self, usb_tar):
        # check if the boot selector is the same from the USB clone image
        # and the running switch system
        usb_fd = usb_tar.open_file('scratch/bootsel')
        usb_bootsel = usb_fd.read().strip()
        usb_fd.close()
        with open('/proc/extr/nvram/bootsel', 'r') as fd:
            lcl_bootsel = fd.read().strip()
        log.debug('lcl sel={}, usb sel={}'.format(lcl_bootsel, usb_bootsel))
        if lcl_bootsel == usb_bootsel:
            return False
        return True

    def usb_clone_from_file_cpio(self, usb_tar, cpio_archive, dest_dir):
        log.debug('cpio_archive={}, dest_dir={}'.format(cpio_archive, dest_dir))

        start_time = time()

        # Untar the archive and place it in /scratch
        scratch_file = '/{}'.format(cpio_archive)
        self.usb_clone_from_file_copy(
                usb_tar,
                cpio_archive,
                scratch_file)

        # if the dest_dir is a directory, mount it as R/W
        # then remove all contents before we replace it with
        # the contents from the tar file
        if isdir(dest_dir) is True:
            log.debug('dest_dir={} is a directory'.format(dest_dir))
            if not access(dest_dir, W_OK):
                self.system_call('mount -o remount,rw {}'.format(dest_dir))

            # Have to be careful of empty directory
            self.system_call('rm -rf {}/*'.format(dest_dir))
        else:
            log.debug('dest_dir={} is not a directory'.format(dest_dir))

        # Populate the dest_dir
        chdir(dest_dir)
        self.system_call('cpio -idu -F {}'.format(scratch_file), suppress_output=True)
        chdir(self.cwd)

        # Get rid of the scratch archive
        os_remove(scratch_file)

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))

    def usb_clone_from_file_untar(self, usb_tar, tar_dir, dest_dir, exclude=None, rmsubdirs=True):
        log.debug('tar_dir={}, dest_dir={}, exclude={}, rmsubdirs={}'.format(
            tar_dir,
            dest_dir,
            exclude,
            rmsubdirs))

        path = '{}{}'.format(dest_dir, tar_dir)

        # some files have switch specific local significance and need to be preserved
        preserve_file_list = []
        for fname in ['system.cfg']:
            preserve_file_list.append('{}/{}'.format(tar_dir, fname))
        keep_file_dict = self.read_preserve_file(dest_dir, preserve_file_list)

        # if the filename is a directory, mount it as R/W
        # then remove all contents before we replace it with
        # the contents from the tar file
        if isdir(path) is True:
            log.debug('path={} is a directory'.format(path))
            if not access(path, W_OK):
                self.system_call('mount -o remount,rw {}'.format(path))
            if rmsubdirs:
                self.system_call('rm -rf {}/*'.format(path))
        else:
            log.debug('path={} is not a directory'.format(path))

        # extract the information from the tar file into the
        # destination

        start_time = time()
        while True:
            try:
                usb_tar.extract(
                        dst_path=dest_dir,
                        include='^{}'.format(tar_dir),
                        exclude=exclude)
            except Exception as e:
                log.debug(e)
                continue
            break

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))

        # remove any preserved files that may have been copied
        self.remove_preserve_file(dest_dir, preserve_file_list)

        # restore any local files that needed to be preserved
        self.write_preserve_file(dest_dir, keep_file_dict)

    @staticmethod
    def usb_is_master_compatible(usb_tar):
        try:
            usb_fd = usb_tar.open_file(XDB.USB_MASTER_VERSION.strip('/'))
        except:
            return False

        # If the master version file is present, it's compatible
        usb_fd.close()
        return True

    def usb_are_systems_compatible(self, usb_tar):
        # check if usb clone image is compatible with this one
        # Look in /scratch/cpuinfo on both systems for specific
        # infomation that must match
        with open('/proc/cpuinfo', 'r') as fd:
            lcl_cpuinfo = fd.readlines()
            log.debug('local cpuinfo= {}'.format(json_dumps(lcl_cpuinfo, indent=2)))
        try:
            usb_fd = usb_tar.open_file('scratch/cpuinfo')
        except Exception as e:
            log.debug(e)
            return False
        rmt_cpuinfo = usb_fd.readlines()
        log.debug('usb cpuinfo= {}'.format(json_dumps(rmt_cpuinfo, indent=2)))
        usb_fd.close()

        # search for key words that are unique to a cpu type
        # i.e. the keyword only exist on one cpu type and not the other
        # e.g. MIPS CPUs have the keyword 'isa' while intel has 'flags'
        for cpu_key in ['isa', 'flags']:
            for cpu_line in lcl_cpuinfo:
                if cpu_line.startswith(cpu_key):
                    # found matching keyword, check remote system
                    break
            else:
                # none of the lines matched
                continue

            # found a matching keyword in the local system
            # does the remote system have the same keyword?
            for cpu_line in rmt_cpuinfo:
                if cpu_line.startswith(cpu_key):
                    return True

            # the remote system does not have a matching keyword
            return False

        # local system doesn't match any of the known keywords
        return False

    def usb_are_root_fs_compatible(self, usb_tar):
        # System must be block-root (EXOS 30.3 or later)
        # -- OR --
        # System must not be block-root
        lcl_block_root, lcl_both_same = self.is_block_root(self.lcl_dm_sysCommon)
        if lcl_both_same is not True:
            return False

        usb_block_root = True
        for root in self.usb_roots:
            try:
                usb_fd = usb_tar.open_file('scratch/{}'.format(root[1]))
                usb_fd.close()
            except:
                usb_block_root = False
                pass
        if lcl_block_root == usb_block_root:
            self.block_root = lcl_block_root
            return True
        else:
            return False

    def usb_stacking_modes_are_aligned(self, usb_tar):
        # if only the exos images are being cloned, it doesn't matter
        # if the stacking modes aligh
        if self.args.exos_only:
            return True

        # read the environment stored on the USB to match
        # the EXOS_STACK_MODE environment variable
        try:
            usb_fd = usb_tar.open_file('scratch/environ')
        except Exception as e:
            log.debug(e)
            if self.is_stacking_enabled():
                self.display_box([
                    'Cloning a stack from USB is not possible with this USB image.',
                    'The USB clone image was made with a previous clone.py version.',
                    'Cloning NOT DONE'],
                    border='X')
                return False
            else:
                self.display_box([
                    'CAUTION',
                    'The USB clone image was made with a previous clone.py version.',
                    'If the USB configuration came from a stack,'
                    'it will not be used for this switch.',
                    ],
                    border='-')
                return True
        # create a key/value environment dictionary from the remote environ file
        # each environment var is null terminated
        for entry in usb_fd.read().split('\0'):
            k, __, v = entry.partition('=')
            self.rmt_environ[k] = str(v)
        usb_fd.close()

        if getenv('EXOS_STACK_MODE') == self.rmt_environ.get('EXOS_STACK_MODE'):
            return True
        return False

    def usb_copy_partitions(self, srcdir, dstdir, exclude=None, rmsubdirs=True):
        self.system_call('mount -o remount,rw {}'.format(dstdir))
        if rmsubdirs:
            self.system_call('rm -rf {}/*'.format(dstdir))

        exclude_file = '/tmp/usbexclude'
        with open(exclude_file, 'w') as fd:
            print >> fd, exclude if exclude else ''

        self.system_call('tar -cO -C {srcdir} -X {exclude_file} . | tar -xf - -C {dstdir}'.format(
            srcdir=srcdir,
            exclude_file=exclude_file,
            dstdir=dstdir))


# **********************************************************************
# This class is invoked in the expy context via the EXOS CLI: create process
# **********************************************************************
class CloneMasterExpy(CloneBaseExpy):
    # this class contains the functions needed to support the cloning master (server)
    # it must be running as a process on the switch that serves the cloning clients

    def __init__(self):
        super(CloneMasterExpy, self).__init__()
        self.clone = None

    def __call__(self):
        self.args = self.get_params()
        self.set_log_level()

        log.debug('Starting')

        # cleanup from cloning stack
        try:
            os_remove(CLONE_STK_SLOTS_FILE)
        except Exception:
            pass

        # re-nice the server to enable clients to clone quickly
        # cmd = 'renice -10 {}'.format(getpid())
        # self.system_call(cmd)

        if self.args.serialno:
            # the transferred config file may have a master process stored
            # This will cause the switch to start the master process
            # We use the serial number on the master command line to match to our
            # serial number. If they do not match, then delete the master process
            if self.args.serialno != self.get_serial_number():
                log.debug('master serial number does not match {} {}'.format(
                    self.args.serialno,
                    self.get_serial_number()))
                self.ip_cleanup()
                self.process_cleanup()
                self.exos_clicmd('save configuration')
                return

        # memory override during cloning
        '''
        mem_pct = self.process_group_limit()
        if mem_pct is not None:
            cmd = 'configure process group other memory-limit {}'.format(
                max(mem_pct + 5, 30))
            self.exos_clicmd(cmd)
        '''

        # self.exos_clicmd('save configuration')
        self.cm_startup()

        # open a server socket for all VRs
        addr = ('0.0.0.0', XDB.SOCKET_PORT)
        server_list = []
        for vr in [0, 1, 2]:
            s = threading.Thread(
                target=self.master_socket_server,
                name='{}-{}'.format(addr, vr),
                args=(addr, vr))
            s.start()
            server_list.append(s)

        # wait here until all vr threads are complete
        for s in server_list:
            s.join()
            log.debug('server {} complete'.format(s.name))
        log.debug('Exit. Should not be here')

    def master_socket_server(self, addr, vr):
        log.debug('Starting serv at {} vr {}'.format(addr, vr))
        environ["EXOS_VR_ID"] = str(vr)
        sock = socket(AF_INET, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, 37, vr)
        sock.settimeout(XDB.MASTER_SOCKET_TIMEOUT)
        try:
            sock.bind(addr)
        except error as e:
            log.debug('Exception during socket.bind {}'.format(e))
            return

        # the master can support 8 simultaneous cloning operations
        sock.listen(7)

        # serve requests
        # each request gets it's own thread
        try:
            while True:
                (conn, conn_addr) = sock.accept()
                log.debug('accepted connection from {}'.format(conn_addr))
                worker = threading.Thread(
                    target=self.master_thread,
                    name=conn_addr,
                    args=(conn, conn_addr))
                worker.start()
        except Exception as msg:
            log.debug('master exception: {}'.format(msg))

        sock.close()
        sock = None

    # this functions and the ones that are called from it
    # run in its own thread
    # each request is a unique thread
    def master_thread(self, conn, conn_addr):
        # get which directories are needed by client
        # E.g.
        # {
        #     'root':'/',
        #     'dirs':['exos','boot', 'config'],
        #     'partboot': '1' or '2',
        #     'dmSystem': dm.dm_system structure from CM
        # }
        client_version, method, rqst_params = self.jsonrpc_recv(conn)

        rqst_dict = {
                XDB.TAR: self.send_tar_output,
                XDB.CAT: self.send_single_file,
                XDB.CLI: self.send_cli_response,
                XDB.SHELL: self.send_shell_response,
                XDB.CPIO: self.send_cpio_output,
            }
        if self.is_client_compatible(client_version):
            func = rqst_dict.get(method)
            if func:
                func(conn, rqst_params)

        try:
            conn.close()
        except Exception:
            pass

    @staticmethod
    def send_master_cmd(conn, cmd):
        log.debug(cmd)

        start_time = time()
        try:
            subprocess_check_call(cmd, stdout=conn.fileno(), shell=True)
        except subprocess_CalledProcessError as e:
            log.debug('{} command failed'.format(e.cmd))
            return False

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))
        return True

    def send_cpio_output(self, conn, rqst_params):
        # Create CPIO archive of the file(s) and send the output
        # over the socket to the client
        root_dir = rqst_params.get(XDB.RQST.ROOT)
        partition = rqst_params.get(XDB.RQST.DIRS)[0]
        cmd = 'find . | cpio -oH newc 2>/dev/null'
        chdir('{}{}'.format(root_dir, partition))
        ret = self.send_master_cmd(conn, cmd)
        chdir(self.cwd)
        return ret

    def send_tar_output(self, conn, rqst_params):
        # tar up the requested directories and send the output
        # over the socket to the client
        root_dir = rqst_params.get(XDB.RQST.ROOT)
        exclude = rqst_params.get(XDB.RQST.EXCLUDE)
        exclude_file = '/tmp/usbexclude'
        with open(exclude_file, 'w') as fd:
            print >> fd, exclude if exclude else ''

        cmd = 'tar -cO -C {root} -X {exclude_file} {dirs} 2>/dev/null'.format(
            root=root_dir,
            exclude_file=exclude_file,
            dirs=' '.join(rqst_params.get(XDB.RQST.DIRS)))

        log.debug(cmd)

        start_time = time()
        try:
            subprocess_check_call(cmd, stdout=conn.fileno(), shell=True)
        except subprocess_CalledProcessError as e:
            log.debug('{} command failed'.format(e.cmd))
            return False

        log.debug('Elapse time {} seconds'.format(
            time() - start_time))
        return True

    def send_single_file(self, conn, rqst_params):
        # the client has requested a single file from the master
        try:
            with open(rqst_params, 'rb') as fd:
                conn.sendall(fd.read())
        except Exception:
            return False
        return True

    def send_cli_response(self, conn, rqst_params):
        # the client has requested a CLI command.
        # The response is sent over the socket to the client
        reply = self.exos_clicmd(rqst_params)
        conn.sendall(reply)

    def send_shell_response(self, conn, rqst_params):
        # run a linux shell command and send the response
        log.debug(rqst_params)
        try:
            subprocess_check_call(rqst_params, stdout=conn.fileno(), shell=True)
        except subprocess_CalledProcessError as e:
            log.debug('{} command failed'.format(e.cmd))
            return False

        return True

    def ip_cleanup(self):
        # this happens when the master master is started on the client
        # after the config file is transferred
        # it's an indication that the master config file is being used
        # on the client and we should clean up any master IP addresses
        # for the mgmt and default vlans
        # print 'Final processing'
        # print 'Unconfiguring IP address from mgmt and default VLANs'
        for vlan in ['mgmt', 'default']:
            while True:
                ipaddr = self.get_vlan_ip(vlan)
                if ipaddr == '0.0.0.0':
                    break
                try:
                    self.exos_clicmd('unconfigure {} ipaddress').format(vlan)
                except Exception:
                    sleep(1)

        '''
        for retry in xrange(10):
            try:
                self.exos_clicmd('save configuration')
                break
            except Exception:
                sleep(3)
        '''

    @staticmethod
    def is_client_compatible(client_version):
        # For now, if we receive a valid version from a client,
        # it is considered compatible/
        if client_version is None:
            return False
        elif client_version == '0.0.0.0':
            log.debug('\nMaster received request from incompatible client. '
                      'Client must be running clone version 1.2.0.1 or later.\n')
            return False
        else:
            return True


# **********************************************************************
# This class is invoked using the EXOS CLI: run script <script>
# **********************************************************************
class CloneRunScript(CloneCommonBase):
    # This class is run in the context of the CLI
    # is is the interface when the user enters:
    #   run script clone.py <options>

    def __init__(self):
        super(CloneRunScript, self).__init__()
        self.args = None
        self.vr = None
        self.stack_mode = None
        self.slot_list = []

    def exos_clicmd(self, cmd, args=None):
        # interface to EXOS CLI in the CLI context
        # log.debug(cmd)
        if isinstance(cmd, str):
            reply = exsh.clicmd(cmd, capture=True, args=args)
        elif isinstance(cmd, list):
            reply = ''
            for c in cmd:
                reply += exsh.clicmd(c, capture=True, args=args)
        # log.debug(reply)
        return reply

    def slotlist(self, slots):
        if slots == 'all':
            return slots

        try:
            slot_set = self.range_check(slots, 1, 8)
        except Exception as msg:
            print 'Slot:', msg
            raise

        my_slot = self.get_my_slot()
        if int(my_slot) in slot_set:
            print 'Slot {} cannot clone itself'.format(my_slot)
            raise ValueError

        return slot_set

    def stacking_slot(self, slots):
        try:
            return self.range_check(slots, 0, 8)
        except Exception as msg:
            print msg
            raise

    def get_params(self):
        # these are the CLI options to all
        # run script clone.py <options>

        # determine if we are running in a stacking environment
        self.stack_mode = self.is_stacking_enabled()

        if self.stack_mode is True and self.is_stack_master() is not True:
            print 'The {} application can only be run from the stack master'.format(
                XDB.PROCESS_NAME)
            raise SystemExit

        parser = argparse_ArgumentParser(prog=XDB.PROCESS_NAME)
        parser.set_defaults(slotlist=[])

        parser.add_argument('-d', '--debug',
                            help='Enable debug',
                            action='store_true',
                            default=False)

        subparsers = parser.add_subparsers(dest='role')

        subparsers.add_parser('master',
                              help='Start the remote cloning server on this switch')

        subparsers.add_parser('stop',
                              help='Stop the %(prog)s application')

        # subparsers.add_parser('restart',
        #                       help='Restart the %(prog)s application. Useful after upgrade')

        subparsers.add_parser('show',
                              help='Show the running status of %(prog)s.')

        if self.stack_mode is True:
            self.slot_list = self.get_slot_list()
            self.slot_list = ExosSync.compatible_stacking_slots(self.slot_list)
            if self.slot_list:
                param_slot_list = [str(x) for x in self.slot_list]
                if len(self.slot_list) > 1:
                    param_slot_list.append('all')
            else:
                param_slot_list = []

            slot_grp = subparsers.add_parser(
                    'slot',
                    help='Clone other slots in the stack to this switch')

            if param_slot_list:
                slotlist_help_msg = 'Compatible slot numbers {}. "all" for all compatible slots'.format(','.join(param_slot_list))
            else:
                slotlist_help_msg = 'No compatible slots found'

            slot_grp.add_argument(
                    'slotlist',
                    help=slotlist_help_msg,
                    type=self.slotlist,
                    default=[])

            slot_grp.add_argument(
                    '-f', '--force',
                    help='Force the cloning operation. Do not ask for confirmation',
                    action='store_true',
                    default=None)

            slot_grp.set_defaults(virtual_router=1)

        client_grp = subparsers.add_parser(
                'from',
                help='Cloning this switch from the <ipaddress> provided.')

        client_grp.add_argument(
                '<ipaddress>',
                help='The IP address of the master switch you are cloning to this switch',
                default=None)

        client_grp.add_argument(
                '-f', '--force',
                help='Force the cloning operation. Do not ask for confirmation',
                action='store_true',
                default=None)

        if self.stack_mode is not True:
            client_grp.add_argument(
                    '-s', '--stacking_slot',
                    help='Also clone stacking information from a stack slot. '
                    'Slot 0 finds the lowest available slot number',
                    type=self.stacking_slot,
                    default=None)

            client_grp.add_argument(
                    '-M', '--stacking_master',
                    help='For stacking, enable this switch to be master_capable',
                    action='store_true',
                    default=False)

        client_grp.add_argument(
                '-e', '--exos_only',
                help='Only clone EXOS partitions. Do not clone the configuration',
                action='store_true',
                default=False)

        usb_grp = subparsers.add_parser(
                'usb',
                help='Cloning this switch to/from the usb memory at {}'.format(XDB.USB_DIR))

        usb_grp.add_argument(
                '-f', '--force',
                help='Force the cloning operation. Do not ask for confirmation',
                action='store_true',
                default=None)

        usb_grp.add_argument(
                '-e', '--exos_only',
                help='Only clone EXOS partitions. Do not clone the configuration',
                action='store_true',
                default=False)

        usb_options = usb_grp.add_mutually_exclusive_group()

        usb_options.add_argument(
                '-i', '--usb_input',
                help='The clone input file name on {}<file>'.format(XDB.USB_DIR),
                type=str,
                default=None)

        usb_options.add_argument(
                '-o',
                help='Create a clone of this switch in {}<file>'.format(XDB.USB_DIR),
                dest='usb_output',
                action='store_true',
                default=None)

        usb_options.add_argument(
                '-v', '--usb_file',
                help='Display the EXOS versions contained in a clone file {}'.format(XDB.USB_DIR),
                type=str,
                default=None)

        return parser.parse_args()

    def __call__(self):
        # this is the entrypoint when running
        # run script clone.py <>
        # depending on the role of the switch (standalone or stacking)
        # different options apply

        try:
            self.args = self.get_params()
        except Exception:
            raise
        if self.stack_mode is True:
            self.args.stacking_slot = None
            self.args.stacking_master = None

        self.set_log_level()
        print('{name}: {version}'.format(
            name=XDB.PROCESS_NAME,
            version=__version__))
        log.debug('{name}: {version}'.format(
            name=XDB.PROCESS_NAME,
            version=__version__))

        # myargv will collect the process options when we perform the exos
        # create process
        # command
        myargv = []
        if self.args.debug:
            myargv.append('-d')

        # This translation table maps the CLI options to the function to call
        role_table = {
            'master': self.master_role,
            'from': self.client_role,
            'stop': self.stop_role,
            # 'restart': self.restart_role,
            'show': self.show_role,
            'slot': self.stack_master_role,
            'usb': self.usb_role,
            }
        log.debug(self.args)
        try:
            role_table.get(self.args.role)(myargv)
        except Exception as e:
            print e
            print 'ERROR: unknown cloning option, Contact Extreme to report this issue'
        return

    def create_process(self, myargv):
        # create the EXOS expy backend process
        # this dance is required to prevent EXOS from crashing
        cmd = [
            'create process {0} python-module {0} start on-demand -- {1}'.format(
                XDB.PROCESS_NAME, ' '.join(myargv)),

            'delete process {0}'.format(XDB.PROCESS_NAME),

            'create process {0} python-module {0} start on-demand -- {1}'.format(
                XDB.PROCESS_NAME, ' '.join(myargv))
            ]
        # how we start depends on if stacking is enabled
        if self.is_stacking_enabled():
            # only start the process for this slot
            cmd.append('start process {} slot {}'.format(XDB.PROCESS_NAME, self.get_my_slot()))
        else:
            # standalone, no slot parameter
            cmd.append('start process {}'.format(XDB.PROCESS_NAME))

        self.exos_clicmd(cmd)

    def delete_process(self):
        # create the EXOS expy backend process
        # this dance is required to prevent EXOS from crashing
        self.exos_clicmd('delete process {0}'.format(XDB.PROCESS_NAME))

    # #############################################################
    # slot (stack master)
    # #############################################################
    def stack_master_role_thread(self, myargv, slot):
        # invoked for each stacking slot
        print 'Cloning slot {} started'.format(slot)
        remote_slot = ExosSync(slot)
        '''
        try:
            remote_slot = ExosSync(slot)
        except Exception as e:
            log.debug('Did not connect with slot {}'.format(slot))
            return
        '''

        ver = remote_slot.version()
        log.debug(ver)
        rc, rc_errno = remote_slot.system("rm -f /scratch/cln.py*")
        rc, rc_errno = remote_slot.system("rm -f /config/cln.py*")

        # copy myself to remote system
        (__, ext) = splitext(__file__)
        remote_slot.copy(__file__, '/scratch/cln{}'.format(ext))

        cmd = '/exos/bin/expy -m cln -- {} -c -v1 -i{}'.format(
            '-d' if self.args.debug is True else '',
            '10.0.{}.2'.format(self.get_my_slot()))
        try:
            rc, rc_errno = remote_slot.system(cmd, expect_error=True)
        except socket_timeout as timeout_err:
            print '\nError: {}'.format(timeout_err)
            print 'Slot {} cloning FAILED'.format(slot)
            return
        if rc is None:
            # assume socket closed with a reboot
            pass
        elif rc < 0:
            log.debug('remote system returned failure code {}'.format(rc))
        print '\nSlot {} cloning COMPLETE'.format(slot)

    def stack_master_role(self, myargv):
        # The user has requested cloning operation on a number of slots.
        #
        # Either the operation was started by a user, or this is a continuation
        # of cloning a stack.
        # If cloning a stack, then the file CLONE_STK_SLOTS_FILE is present
        # all of the slots must be present before continuing the operation
        #
        # self.args.slot_list contains a list of slot numbers
        # start the cloning server on the master and create a thread
        # for each slot specified

        if isfile(CLONE_STK_SLOTS_FILE):
            with open(CLONE_STK_SLOTS_FILE, 'r') as fd:
                self.slot_list = json_load(fd).get(SLOTLIST)
                self.args.slotlist = self.slot_list

            # slots may be rebooting during stack cloning operation
            # wait until all slots are available
            log.debug('{} slot list {}'.format(CLONE_STK_SLOTS_FILE, self.slot_list))
            while True:
                active_list = ExosSync.compatible_stacking_slots(self.slot_list)
                log.debug('Active slot list {}'.format(self.slot_list))
                if len(active_list) == len(self.slot_list):
                    break
                msg = 'Waiting for slots to be ready for cloning'
                print msg
                log.debug(msg)
                sleep(10)
            #self.exos_clicmd('enable led locator timeout none slot all')

        if self.args.slotlist and 'all' in self.args.slotlist:
            self.args.slotlist = self.slot_list

        if not self.slot_list:
            print "No compatible slots can be found for this cloning application"
            return None

        if self.args.force is not True:
            msg = ['C A U T I O N',
                   'Cloning will erase all contents on these slots:',
                   ','.join([str(x) for x in self.args.slotlist]),
                   'The switch contents of this stacking master',
                   'will replace the contents of these switches',
                   ]

            self.display_box(msg, border='+')
            while True:
                yes_no = raw_input('Do you want to continue cloning? [y/N]: ').strip().lower()
                log.debug(yes_no)
                if yes_no not in ['', 'y', 'yes', 'n', 'no']:
                    print 'unknown input', yes_no
                    continue
                if len(yes_no) and yes_no[0] == 'y':
                    break
                return

        # start the cloning server
        myargv.append('-m')
        myargv.append('-n{}'.format(self.get_serial_number()))
        self.create_process(myargv)

        # Do one slot at a time. Stack link connectivity may be lost for some slots
        # if we do more that one at a time
        for slot in self.args.slotlist:
            # print progress dots to entertain the user
            dots = self.start_progress_dots(slot)

            self.stack_master_role_thread(myargv, slot)

            # stop printing progress dots
            self.stop_progress_dots()
            dots.join()
        self.delete_process()

    # #############################################################
    # master
    # #############################################################
    def master_role(self, myargv):
        # run script clone.py master
        if self.is_process_running():
            print '{} is already running'.format(XDB.PROCESS_NAME_PY)
        else:
            myargv.append('-m')
            myargv.append('-n{}'.format(self.get_serial_number()))

            self.create_process(myargv)
            print '{} is started as cloning master'.format(XDB.PROCESS_NAME_PY)
            print 'Use "stop" option to stop cloning master services'
            print

    # #############################################################
    # client (from)
    # #############################################################
    def client_role(self, myargv):
        # run script clone.py from <>

        if self.is_process_running():
            print '{} is already running'.format(XDB.PROCESS_NAME_PY)
            print 'Restarting'
            self.stop_role(myargv)

        ipaddress = vars(self.args).get('<ipaddress>')

        if self.args.force is not True:
            msg = ['C A U T I O N']
            if self.args.exos_only is True:
                exos_only_msg = [
                   'Cloning will replace the EXOS partitions on this switch',
                   'with the contents of the master switch {}'.format(ipaddress),
                   ]
                msg += exos_only_msg
            else:
                all_switch_msg = [
                   'Cloning will replace the EXOS partitions and configuration',
                   'on this switch with the contents of the master switch {}'.format(ipaddress),
                   ]
                msg += all_switch_msg

            if self.args.stacking_slot is not None:
                stk_msg = [
                    '',
                    'STACKING',
                    'You have requested this switch to be cloned to stack {}'.format(ipaddress),
                    ]

                if self.args.stacking_master is True:
                    stk_msg.append('as a stacking master')

                stk_msg2 = [
                    'Switches have a variety of stacking cabling options. See:',
                    ' ',
                    'configure stacking-support ...',
                    'and',
                    'enable stacking-support',
                    ' ',
                    'The stacking-support options MUST already be configured before cloning',
                    'for stack connectivity to work correctly'
                    ]
                msg += stk_msg
                msg += stk_msg2

            self.display_box(msg, border='+')
            while True:
                yes_no = raw_input('Do you want to continue cloning? [y/N]: ').strip().lower()
                log.debug(yes_no)
                if yes_no not in ['', 'y', 'yes', 'n', 'no']:
                    print 'unknown input', yes_no
                    continue
                if len(yes_no) and yes_no[0] == 'y':
                    break
                return

        # determine if address is IPv4 or IPv6
        for sock_type in [AF_INET, AF_INET6]:
            try:
                inet_pton(sock_type, ipaddress)
                break
            except Exception:
                continue
        else:
            print 'Invalid IP address provided {}'.format(ipaddress)
            return

        for retry in xrange(2):
            if self.client_check_connection(sock_type, ipaddress) is not None:
                # IP connectivity is available
                break
            # do either the mgmt or default vlan have an IP address to connect with
            # the clone master? If not, enable DHCP
            for vlan in ['mgmt', 'default']:
                ipaddr = self.get_vlan_ip(vlan)

                log.debug('vlan {} ipaddr {}'.format(vlan, ipaddr))

                if ipaddr != '0.0.0.0':
                    continue
            else:
                # Neither vlan has an IP address, lets try enableing DHCP
                self.exos_clicmd('enable dhcp vlan mgmt')
                self.exos_clicmd('enable dhcp vlan default')
                # let DHCP do it's thing
                sleep(5)
        else:
            print 'Cannot connect to address {}'.format(ipaddress)
            print 'Check if cloning master is enabled on {}'.format(ipaddress)
            return

        myargv.append('-c')
        myargv.append('-i{}'.format(ipaddress))
        myargv.append('-v{}'.format(str(self.vr)))
        if self.args.stacking_slot is not None:
            myargv.append('-s{}'.format(','.join([str(x) for x in self.args.stacking_slot])))
        if self.args.stacking_master is True:
            myargv.append('-M')
        if self.args.exos_only is True:
            myargv.append('--exos_only')

        self.create_process(myargv)
        print '{} is started as cloning client.'.format(XDB.PROCESS_NAME_PY)
        print 'This switch will become a copy of {}'.format(ipaddress)
        print 'DO NOT REMOVE POWER or REBOOT the switch until the operation is COMPLETE'
        print

    def client_check_connection(self, sock_type, ipaddress):
        # determine if we can reach the IP address on a vr
        # 0-VR-Mgmt
        # 1-VR-Control (internal for stacking)
        # 2-VR-Default (front panel)
        addr = (ipaddress, XDB.SOCKET_PORT)
        for self.vr in [0, 2]:
            environ["EXOS_VR_ID"] = str(self.vr)
            sock = socket(sock_type, SOCK_STREAM)
            sock.setsockopt(SOL_SOCKET, 37, self.vr)
            sock.settimeout(3)
            log.debug('Trying to connect to {} vr {}'.format(addr, self.vr))
            try:
                sock.connect(addr)
                return sock
            except Exception:
                continue
        return None

    # #############################################################
    # usb
    # #############################################################
    def usb_role(self, myargv):
        # run script clone.py usb
        log.debug('Called')

        if self.usb_is_present() is False:
            print 'USB memory is not present'
            print 'Insert USB memory into the USB slot'
            return

        if self.is_process_running():
            self.stop_role(myargv)

        myargv.append('-u')
        if self.args.usb_file:
            self.usb_role_version(myargv)
        elif self.args.usb_output:
            self.usb_role_to_file(myargv)
        elif self.args.usb_input:
            self.usb_role_from_file(myargv)
        else:
            print 'Missing USB option. usb -h for options'
            return

    @staticmethod
    def usb_is_present():
        # detect the presence of the USB stick if the mount directory exists
        if isdir(XDB.USB_DIR) is True:
            return True
        return False

    def usb_is_file_valid(self, filename):
        # determine if the file has valid content
        log.debug('Called')

        # first see if we were given a relative or absolute path
        for usb_dir in ['', XDB.USB_DIR]:
            usb_path = '{}{}'.format(usb_dir, filename)
            log.debug(usb_path)
            if isfile(usb_path):
                log.debug('found {}'.format(usb_path))
                break
        else:
            raise IOError('Cannot find {}'.format(filename))

        if ExpyTar.is_tar(usb_path) is True:
            return usb_path

        raise IOError('Invalid file format')

    @staticmethod
    def usb_is_valid_file_cleanup():
        # cleanup temp files after checking versions
        for f in [XDB.VER1, XDB.VER2]:
            try:
                os_remove('{}/{}'.format(XDB.TMP_DIR, f))
            except Exception:
                pass

    def usb_start_backend(self, myargv):
        # start the back end expy process
        self.create_process(myargv)

        # print progress dots to entertain the user
        self.start_progress_dots(self.get_my_slot())

        while True:
            sleep(1)
            if self.is_process_running():
                continue
            break

        # stop printing progress dots
        self.stop_progress_dots()
        print

    def usb_role_version(self, myargv):
        log.debug('Called')

        try:
            usb_path = self.usb_is_file_valid(self.args.usb_file)
        except Exception as msg:
            print msg
            return

        usb_tar = ExpyTar()
        usb_tar.open(usb_path, 'r')

        print 'File:', usb_path
        print 'Contains:'

        for f in [XDB.VER1, XDB.VER2]:
            try:
                fd = usb_tar.open_file(f)
                spec_lines = fd.readlines()
                log.debug(spec_lines)
                fd.close()
            except Exception:
                print 'Could not find', f
                return

            print 'EXOS:'
            for line in spec_lines:
                param_type, __, param_value = line.strip().partition('=')
                param_value = param_value.rstrip(':')
                if param_type in ['platform', 'linkDate', 'pkgname']:
                    print '\t', param_value

    def usb_role_to_file(self, myargv):
        usb_output_file = XDB.USB_FILENAME.format(
            serno=self.get_serial_number(),
            t=strftime('%Y-%m-%d_%H%M')
            )
        if self.args.exos_only is True:
            msg = [
                'Clone EXOS partitions on this switch to the file:',
                usb_output_file,
                ]
        else:
            msg = [
                'Clone EXOS and configuration partitions on this switch to the file:',
                usb_output_file,
                ]
        if self.args.force is not True:
            self.display_box(msg, border='+')
            if self.get_yes_no() is False:
                return

        myargv.append('--usb_output')
        myargv.append(usb_output_file)
        if self.args.exos_only is True:
            myargv.append('--exos_only')

        self.usb_start_backend(myargv)

        cmd = 'ls {}'.format(usb_output_file)
        print self.exos_clicmd(cmd)

        self.display_box(['Cloning COMPLETE'], border='*')

        return

    def usb_role_from_file(self, myargv):
        try:
            usb_path = self.usb_is_file_valid(self.args.usb_input)
        except IOError as msg:
            print msg
            return

        msg = ['C A U T I O N']
        if self.args.exos_only is True:
            exos_only_msg = [
               'Cloning will replace the EXOS partitions on this switch',
               'with the contents of the usb file',
               usb_path
               ]
            msg += exos_only_msg
        else:
            all_switch_msg = [
               'Cloning will replace the EXOS partitions and configuration',
               'on this switch with the contents of the usb file',
               usb_path
               ]
            msg += all_switch_msg

        if self.args.force is not True:
            self.display_box(msg, border='+')
            if self.get_yes_no() is False:
                return

        print 'DO NOT REMOVE POWER or REBOOT the switch until the operation is COMPLETE'
        print 'Switch will reboot when cloning is COMPLETE'

        myargv.append('--usb_input')
        myargv.append(usb_path)
        if self.args.exos_only is True:
            myargv.append('--exos_only')

        self.usb_start_backend(myargv)

        self.display_box(['Cloning COMPLETE'], border='*')

        return

    # #############################################################
    # stop
    # #############################################################
    def stop_role(self, myargv):
        # run script clone.py stop
        if self.is_process_running():
            print 'Stopping {}'.format(XDB.PROCESS_NAME_PY)
            cmd = 'delete process {}'.format(XDB.PROCESS_NAME)
            self.exos_clicmd(cmd)
            print '{} is stopped'.format(XDB.PROCESS_NAME_PY)
        else:
            print '{} is not running'.format(XDB.PROCESS_NAME_PY)

    # #############################################################
    # restart
    # #############################################################
    def restart_role(self, myargv):
        # run script clone.py restart
        if self.is_process_running():
            print 'Restarting {}'.format(XDB.PROCESS_NAME_PY)
            cmd = 'restart process {}'.format(XDB.PROCESS_NAME)
            self.exos_clicmd(cmd, args='n')
            print '{} has been restarted'.format(XDB.PROCESS_NAME_PY)
        else:
            print '{} is not running. Use master or start <ip> option.'.format(
                XDB.PROCESS_NAME_PY)

    # #############################################################
    # show
    # #############################################################
    def show_role(self, myargv):
        # run script clone.py show
        if self.is_process_running():
            print '{:<15} Version: {} is running'.format(XDB.PROCESS_NAME_PY, __version__)
        else:
            print '{:<15} Version: {} is not running'.format(XDB.PROCESS_NAME_PY, __version__)


# **********************************************************************
# Determine the run time context and invoke the proper class
# **********************************************************************
if __name__ == '__main__':
    sys.stdout = sys.stderr
    if i_am_script is True:
        # customer starts with 'run script clone.py' CLI command
        clone = CloneRunScript()
        try:
            clone()
        except (KeyboardInterrupt, SystemExit) as msg:
            pass
    else:
        # Script was started with 'create process' CLI command
        # or invoked directly with expy
        clone = CloneBaseExpy()
        clone()
