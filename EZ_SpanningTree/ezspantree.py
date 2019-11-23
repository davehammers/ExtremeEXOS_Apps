# ******************************************************
#
#  Copyright (c) Extreme Networks Inc. 2016
#  All rights reserved
#
# ******************************************************
'''
ezspantree is designed to make the transistion from EOS to EXOS easier for customers by performing
automatic actions for spanning tree configuration and vlan additions.

When first enabled, either via CLI or run script, ezspantree performs the following actions:
.   CLI: [ enable | disable ] stpd easy-setup
    -   Same concept as easy-setup for stacking. Pick a set of
        configuration options that will satisfy most users

.   Option: port CLI to a standalone script for prior releases
    (16.1, 21.1 possibly 15.7 if MSTP/VLAN support is there)
    -   e.g. run script ezspantree.py
    -   Make this available on github.com/extremenetworks

.   STP easy-setup
    -   config stpd "s0" delete vlan "Default" ports all
    -   disable stpd "s0" auto-bind "Default"
    -   config stpd "s0" mode mstp cist
    -   config stpd "s0" add vlan "Default" ports all
    -   enable stpd "s0" auto-bind vlan "Default"
    -   config stpd "s0" loop-protect event-threshold 3
    -   enable stpd
    -   enable stpd "s0"
    -   Add new capability: As VLANs are created, automatically do the
        following for each new vlan:

.   config stpd "s0" add vlan <vlan> ports all

.   enable stpd "s0" auto-bind vlan <vlan>

.   when the application starts, it scans all VLANs
    -   VLANs that are already attached to stp will not be affected
    -   VLANs that are not attached to stp will be attached to MSTP/CIST

.   The application will automatically restart after a reboot

This module runs in 3 different contexts:
    CLI - imported when CLI [enable | disable] stpd easy-setup
    script - run script ezspantree.py [start | stop | show]
    expy - run as a process to monitor vlan additions

Each context is implemented in it's own class:
    E.g. the CLI context would invoke EzStpdCli()
        run script context invokes EzStpdScript()
        expy invokes  EzStpdExpy()
'''
# attempt to be compatible with Python 3.5
from __future__ import absolute_import, print_function, with_statement

from sys import (
    stdout,
    stderr,
    )
import json
import logging
from logging.handlers import RotatingFileHandler
import argparse
from os.path import (
    isfile,
    splitext,
    basename,
    )

# Determine the context we are running in by trying different imports
try:
    import exoslib
    i_am_cli = True
    import subprocess
    import cmlib
except Exception:
    i_am_cli = False

try:
    import exsh
    i_am_script = True
except Exception:
    i_am_script = False

if i_am_cli is False and i_am_script is False:
    i_am_expy = True
    i_am_exos_pre21 = False
    import threading
    try:
        from exos.api.cmbackend import (cmbackend_init, CmAgent)
        from exos.api import ready
    except Exception:
        i_am_exos_pre21 = True
    from exos.api import vlan
    from exos.api import exec_cli, exec_cli_async
    from exos.api import CLI_EVENT_EXEC_REPLY
    from exos.api import TraceBufferHandler
    import Queue
    import time


################################################################################
# CONSTANTS

__version__ = '2.1.0.4'

# ------------------------------------------------------------
# 2.1.0.4 bpeabody
#   xos0074533 - Include cc_logs directory in 'upload debug'
#   Moved files from /usr/local/cfg to /usr/local/tmp:
#     /usr/local/cfg/cc_logs/ezspantree.txt --> /usr/local/tmp/cc_logs/ezspantree.txt
#     /usr/local/cfg/ezspanconsole.pkt      --> /usr/local/tmp/ezspanconsole.pkt
# ------------------------------------------------------------
# 2.1.0.3 dhammers
#   xos0073423 - When using the old netsight java client to add VLANs, ezspantree does not get notified
# ------------------------------------------------------------
# 2.1.0.2 12-May-2018 dhammers
#   Customer reported issue with show and stop commands on a stack
# ------------------------------------------------------------
# 2.1.0.1 13-Dec-2017 dhammers
#   Customer reported crash on The Hub on EXOS 22.4.1.4
# ------------------------------------------------------------
# 2.0.0.1 9-Sep-2016 dhammers
#    added support for 15.6 thru 16.x
# ------------------------------------------------------------

PROCESS_NAME = 'ezspantree'
LOG_FILENAME = '/usr/local/tmp/cc_logs/ezspantree.txt'
CONSOLE_DEBUG = '/usr/local/tmp/ezspanconsole.pkt'


class Xos(object):
    DEFAULT_STP_NAME = 's0'

    # CONSTANTS for EXOS vlan callbacks
    class VlanPortCallback(object):
        NAME = 'vlan_name'
        ID = 'vlan_id'
        PORT = 'port'
    VPC = VlanPortCallback()


XDB = Xos()


################################################################################
# CLI
# This class is invoked when running in the EXOS CLI context
# It provides the user interacion to:
#   [show | enable | diable} stpd easy-setup
# The CLI simply deos an import ezxpantree, and control is passed to this class
class EzStpdCli(object):
    def __init__(self):
        self.startup_message = [
                'Spanning Tree Easy Setup {}'.format(__version__),
                '- Configures spanning tree s0 mode to MSTP/CIST',
                '- Scans all VLANs',
                '   if a VLAN is not connected to spanning tree, it is added to s0',
                '   if a VLAN is already connected to spanning tree s0, it is updated',
                '   VLANs connected to spanning tree(s) other than s0 are not affected',
                '- Starts a VLAN monitoring process for any new VLANS',
                '   newly created VLANS are automatically added to spanning tree s0',
                ''
                ]

    def __call__(self):
        args = cmlib.getArgs()
        if 'enable' in args:
            self.enable_ezspantree(args)
        elif 'disable' in args:
            self.disable_ezspantree(args)
        elif 'show' in args:
            self.show_ezspantree(args)

    def message_to_user(self, msg, force=False):
        rc = exoslib.show(msg, 1 if force is True else 0)
        if rc < 0:
            raise IOError

    def exos_cmd(self, cmd):
        # issue CLI command to EXOS and return the result
        p = subprocess.Popen(
                ['/exos/bin/exsh', '-n', '0', '-b', '-c', cmd],
                stdout=subprocess.PIPE)
        for line in iter(p.stdout.readline, ''):
            try:
                self.message_to_user(line)
            except IOError:
                p.stdout.close()
                break

    def enable_ezspantree(self, args):
        for line in self.startup_message:
            self.message_to_user(line + '\n', force=True)
        confirm = cmlib.getYesNo('Do you wish to proceed', 0)
        if not confirm:
            return

        self.exos_cmd('run script {0}.py start'.format(PROCESS_NAME))

    def disable_ezspantree(self, args):
        self.exos_cmd('run script {0}.py stop'.format(PROCESS_NAME))

    def show_ezspantree(self, args):
        self.exos_cmd('run script {0}.py show'.format(PROCESS_NAME))


# ############################################################
# common functions for script and expy environments
#
class EzStpdBase(object):
    def __init__(self):
        self.log = logging.getLogger(PROCESS_NAME)
        self.log.setLevel(logging.DEBUG)
        # avoid adding a handler if the logger aleady has one
        if not self.log.handlers:
            # Create the EXOS logging mechanism
            log_fmt = '%(asctime)s:%(levelname)s:%(filename)s:%(funcName)s:%(lineno)s: %(message)s'
            handler = RotatingFileHandler(LOG_FILENAME, mode='w', maxBytes=100*1024, backupCount=3)
            # log info level to file
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter(log_fmt))
            self.log.addHandler(handler)

            if isfile(CONSOLE_DEBUG):
                handler = logging.StreamHandler(stderr)
                # log debug level to console
                handler.setLevel(logging.DEBUG)
                handler.setFormatter(logging.Formatter(log_fmt))
                self.log.addHandler(handler)

    def json_clicmd(self, cmd):
        # issue debug cfgmgr CLI command to EXOS and return the JSON data
        self.log.debug(cmd)
        if i_am_script is True:
            json_result = exsh.clicmd(cmd, capture=True)
        else:
            json_result = exec_cli([cmd], ignore_errors=True)

        try:
            json_dict = json.loads(json_result)
        except Exception as e:
            self.log.warn('JSON format error {}\n{}'.format(e, json_result))
            return None
        # extract and return the data list
        return json_dict.get('data')

    def build_vlan_stp_db(self):
        # create a dictionary by VLAN showing the STP instance.
        # this dictionary will be used to lookup vlans to see if they are already
        # connected to STP
        vlan_stp_dict = {}
        # get a list of all stp instances
        stp_list = self.json_clicmd(
            'debug cfgmgr show next stp.stp_domain_enable stpd_name=None'
            )
        stp_set = set()
        # extract the unique spanning tree names
        for row in stp_list:
            stp_set.add(row['stpd_name'])

        # for each instance, collect the vlans attached to it
        if stp_set:
            for stp_name in stp_set:
                for search_dir in [1, 2, 3]:
                    vlan_list = self.json_clicmd(
                        'debug cfgmgr show next stp.stp_vlan_stats stpd_name={stp_name} search_dir={search_dir} vlan_name=None'.format(
                            stp_name=stp_name,
                            search_dir=search_dir))

                    # build the VLAN/STP dictionary
                    if vlan_list:
                        for vlan_row in vlan_list:
                            if i_am_script is True:
                                self.write_progress_dot()
                            vname = vlan_row['vlan_name']
                            if vname is None:
                                continue
                            vlan_stp_dict[vname] = stp_name

        return vlan_stp_dict


################################################################################
# Script
# This class is invoked when running EXOS
# run script ezspantree.py [start | stop | show]
# it may be invoked directly from the EXOS CLI or as a result of the CLI class
# above.
class EzStpdScript(EzStpdBase):
    def __init__(self):
        super(EzStpdScript, self).__init__()

        self.dot_cnt = 0
        self.startup_message = [
                'Spanning Tree Easy Setup {}'.format(__version__),
                '- Configures spanning tree s0 mode to MSTP/CIST',
                '- Scans all VLANs',
                '   if a VLAN is not connected to spanning tree, it is added to s0',
                '   if a VLAN is already connected to spanning tree s0, it is updated',
                '   VLANs connected to spanning tree(s) other than s0 are not affected',
                '- Starts a VLAN monitoring process for any new VLANS',
                '   newly created VLANS are automatically added to spanning tree s0',
                ''
                ]

    def __call__(self):
        args = self.get_params()
        if args is None:
            self.message_to_user('Error: Missing command line parameters')
            return

        # command line actions function table
        func_dict = {
                'stop':     self.stop_ezspantree,
                'start':    self.start_ezspantree,
                'show':     self.show_ezspantree
                }
        func = func_dict.get(args.action)
        if func is None:
            self.message_to_user('Error: {0}: Unknown command line option {1}'.format(
                       PROCESS_NAME,
                       args.action))
        else:
            func(args)

    def get_params(self):
        # process command line parameters
        parser = argparse.ArgumentParser(
            prog=PROCESS_NAME,
            formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument(
                'action',
                choices=['start', 'stop', 'show'],
                help='start\tStart automatically adding VLANs to spanning tree s0.\nstop\tStop automatically adding VLANs to spanning tree s0.\nshow\tShow the running status of %(prog)s.',
                default=None)

        # catch the -h exception behavior here
        try:
            args = parser.parse_args()
        except SystemExit:
            return None

        return args

    def exsh_clicmd(self, cmd):
        # issue CLI command to EXOS
        self.log.info('command={0}'.format(cmd))
        exsh.clicmd(cmd, capture=False)

    def message_to_user(self, msg):
        print(msg)

    def write_progress_dot(self):
        if self.dot_cnt == 0:
            stdout.write('.')
            stdout.flush()

        if self.dot_cnt == 10:
            self.dot_cnt = 0
        else:
            self.dot_cnt += 1

    def show_ezspantree(self, args):
        if self.is_process_running():
            self.message_to_user('{0}\tVersion: {1}\tprocess is running'.format(
                PROCESS_NAME, __version__))
            self.message_to_user('VLANs are automatically added to spanning tree {stp_name}'.format(
                stp_name=XDB.DEFAULT_STP_NAME))
        else:
            self.message_to_user('{0}\tVersion: {1}\tprocess is not running'.format(
                PROCESS_NAME, __version__))
            self.message_to_user('VLANs are not automatically added to spanning tree {stp_name}'.format(
                stp_name=XDB.DEFAULT_STP_NAME))

    def stop_ezspantree(self, args):
        # stop the EXOS process that monitorys VLAN creation
        if self.is_process_running():
            # if the process is running, issues the EXOS commands to stop it
            self.exsh_clicmd('delete process {pname}'.format(
                pname=PROCESS_NAME))
            self.message_to_user('{pname} stopped'.format(
                pname=PROCESS_NAME))
            # start/stop results in config changes to EXOS.
            # save is needed to make them permanent
            self.exsh_clicmd('save')
        else:
            # process is not running. Let the user know
            self.show_ezspantree(args)
        return

    def yes_no(self, prompt, default_response=False):
        # prompt the user with a question
        # default_response = True, append [n/Y] to prompt
        # default_response = False, append [y/N] to prompt
        # returns True for 'yes', False for 'no' input
        sel_dict = {
                True:   '[n/Y]',
                False:  '[y/N]',
                }
        display_prompt = '{prompt} {choice} '.format(prompt=prompt, choice=sel_dict.get(default_response))
        while True:
            response = raw_input(display_prompt).lower()
            if len(response) == 0:
                return default_response
            if response in ['y', 'ye', 'yes']:
                return True
            if response in ['n', 'no']:
                return False
            self.message_to_user('invalid response {0}'.format(response))

    def start_ezspantree(self, args):
        if self.is_process_running():
            self.message_to_user('{0}\tis already running'.format(PROCESS_NAME))
            answer = self.yes_no('Do you wish to restart the MSTP/CIST configuration?', default_response=False)
            if answer is False:
                return

        for line in self.startup_message:
            self.message_to_user(line)
        answer = self.yes_no('Do you wish to proceed?', default_response=False)
        if answer is False:
            return

        self.start_process(args)
        self.add_vlans_to_stp_at_startup()
        self.exsh_clicmd('save')

    def is_mstp_configured(self):
        cmd = 'debug cfgmgr show one stp.stp_domain stpd_name=s0'
        rslt = self.json_clicmd(cmd)
        if rslt:
            for row in rslt:
                protocol_mode = row.get('protocol_mode')
                if protocol_mode == '3':
                    return True
                break
        return False

    def config_stp_to_mstp(self):
        # this funciton
        #   deletes any associations with stp s0
        #   converts stp s0 to MSTP/CIST mode

        # collect any VLAN associated with stp.
        # if the VLAN is associated with stp s0, remove it from stp
        self.message_to_user('Collecting VLANs assigned to spanning trees. This may take a moment ...')
        vlan_stp_dict = self.build_vlan_stp_db()
        for vname, stp_name in vlan_stp_dict.items():
            self.write_progress_dot()
            if stp_name == XDB.DEFAULT_STP_NAME:
                self.exsh_clicmd('disable stpd {stp_name} auto-bind {vname}'.format(
                    stp_name=XDB.DEFAULT_STP_NAME, vname=vname))
                self.exsh_clicmd('config stpd {stp_name} delete vlan {vname} ports all'.format(
                    stp_name=XDB.DEFAULT_STP_NAME, vname=vname))

        # disable stp s0 while we change the mode to MSTP/CIST
        self.exsh_clicmd('disable stpd {stp_name}'.format(
            stp_name=XDB.DEFAULT_STP_NAME))

        self.message_to_user('\nConfiguring STP {stp_name} to MSTP/CIST'.format(
            stp_name=XDB.DEFAULT_STP_NAME))
        self.exsh_clicmd('config stpd {stp_name} mode mstp cist'.format(
            stp_name=XDB.DEFAULT_STP_NAME))

    def start_process(self, args):
        # this funciton
        #   Check the config of stp s0
        #   looks for any VLANs not attached to stp
        #   addes the VLAN to stp s0
        #   starts the EXOS process to monitor VLAN creations
        if self.is_mstp_configured() is False:
            self.config_stp_to_mstp()
        else:
            self.message_to_user('STP {stp_name} is already configured for MSTP'.format(
                stp_name=XDB.DEFAULT_STP_NAME))

        # Reenable stp s0 with it's new mode
        self.message_to_user('Enabling STP {stp_name}'.format(
            stp_name=XDB.DEFAULT_STP_NAME))
        self.exsh_clicmd('enable stpd')
        self.exsh_clicmd('enable stpd {stp_name}'.format(
            stp_name=XDB.DEFAULT_STP_NAME))

        # was the EXOS VLAN creation monitoring process already running?
        if self.is_process_running():
            # restart the process
            self.exsh_clicmd('restart process {pname}'.format(
                pname=PROCESS_NAME))
            self.message_to_user('{pname} restarted'.format(
                pname=PROCESS_NAME))
            return

        # fall thru if process does not already exist
        fname = splitext(basename(__file__))[0]
        self.exsh_clicmd(
                'create process {pname} python-module {fname} start on-demand'.format(
                    pname=PROCESS_NAME,
                    fname=fname))
        self.message_to_user('{pname} started'.format(
            pname=PROCESS_NAME))

        # this dance below is a work around for an EPM crash when creating
        # this application 'auto'
        # Don't know why it works but starting it on-demand then deleting it,
        # then starting it auto works
        self.exsh_clicmd('start process {pname}'.format(
            pname=PROCESS_NAME))
        self.exsh_clicmd('delete process {pname}'.format(
            pname=PROCESS_NAME))
        self.exsh_clicmd(
                'create process {pname} python-module {fname} start auto'.format(
                    pname=PROCESS_NAME,
                    fname=fname))

    def add_vlans_to_stp_at_startup(self):
        # when this script is first run by the user, there are some
        # one time things that need to happen
        #
        self.message_to_user('Scanning all VLANs')
        self.message_to_user('\tVLANs not connected to STP will be automatically added to {stp_name}\n'.format(
            stp_name=XDB.DEFAULT_STP_NAME))

        # get a dictionary of VLANS connected to stp instances
        vlan_stp_dict = self.build_vlan_stp_db()
        # get a list of all vlans
        vlan_list = self.build_vlan_db()

        # scan each VLAN and see if it already connected to an stp instance
        # build a list of names to display to user
        vname_add_list = []
        for vname in vlan_list:
            stp_name = vlan_stp_dict.get(vname)
            if stp_name is None:
                vname_add_list.append(vname)

        if vname_add_list:
            self.message_to_user('\nThese VLAN(s) will be added to Spanning Tree {stp_name}:'.format(
                    stp_name=XDB.DEFAULT_STP_NAME))
            self.message_to_user(', '.join(vname_add_list))
            self.message_to_user('\nAdding VLAN(s) to Spanning Tree {stp_name}:'.format(
                    stp_name=XDB.DEFAULT_STP_NAME))

        # scan each VLAN and see if it already connected to an stp instance
        for vname in vlan_list:
            stp_name = vlan_stp_dict.get(vname)

            if stp_name is None:
                # VLAN is not connected to stp, add it to stp s0
                self.add_vlan_to_stp(vname)
            elif stp_name == XDB.DEFAULT_STP_NAME:
                # VLAN is already connected to stp s0, update it with the settings we want
                # self.message_to_user('Updating {vname} on Spanning Tree {stp_name}'.format(
                #    vname=vname, stp_name=XDB.DEFAULT_STP_NAME))
                self.update_vlan_stp_settings(vname)

            # VLAN is involved with some other STP instance. Leave it alone
        self.message_to_user('\n')

    def add_vlan_to_stp(self, vname):
        self.write_progress_dot()
        # EXOS CLI commands to add a VLAN to the default stp s0
        self.exsh_clicmd('config stpd {stp_name} add vlan {vname} ports all'.format(
            vname=vname, stp_name=XDB.DEFAULT_STP_NAME))
        self.exsh_clicmd('enable stpd {stp_name} auto-bind vlan {vname}'.format(
            vname=vname, stp_name=XDB.DEFAULT_STP_NAME))

    def update_vlan_stp_settings(self, vname):
        # EXOS CLI commands to update a VLAN already connected to stp s0
        # for now, just do the same thing as add
        self.exsh_clicmd('config stpd {stp_name} add vlan {vname} ports all'.format(
            vname=vname, stp_name=XDB.DEFAULT_STP_NAME))
        self.exsh_clicmd('enable stpd {stp_name} auto-bind vlan {vname}'.format(
            vname=vname, stp_name=XDB.DEFAULT_STP_NAME))

    def is_process_running(self):
        # query EXOS to see if our process already exists
        data = self.json_clicmd('debug cfgmgr show one epm.epmpcb name={pname}'.format(
            pname=PROCESS_NAME))

        if data:
            status = data[0].get('status')
            if status is None:
                return False

            # CM returns SUCCESS if we found the matching record
            if status in ['SUCCESS', 'MORE']:
                self.log.info('Process is running')
                return True

        self.log.info('Process is not running')
        return False

    def build_vlan_db(self):
        # create a list of all existing VLAN names
        vlan_list = []
        vlan_map_list = self.json_clicmd('debug cfgmgr show next vlan.vlanMap vlanList=None')

        if vlan_map_list:
            for vlan_map_row in vlan_map_list:
                vname = vlan_map_row['vlanName']
                if vname is None:
                    continue
                vlan_list.append(vname)
        self.log.debug(vlan_list)
        return vlan_list


################################################################################
# EXPY
#
class EzStpdExpy(EzStpdBase):
    def __init__(self):
        super(EzStpdExpy, self).__init__()

        # root logger
        self.rlog = logging.getLogger('')
        self.rlog.setLevel(logging.INFO)
        self.logHandler = TraceBufferHandler("rlog", 20480)
        self.logHandler.setLevel(logging.INFO)
        self.logHandler.setFormatter(logging.Formatter(
            "%(name)05s:%(funcName)s:%(lineno)s:: %(message)s"))
        if not len(self.rlog.handlers):
            self.rlog.addHandler(self.logHandler)

        # Database
        self.db_conn = None

        # used for CLI polling
        self.vlan_stp_dict = None
        self.cli_reply = []
        self.vlan_map_set = set()

        # threads
        self.dispatcher_thread = None
        self.q = None

    def __call__(self):
        # expy process main

        # create the queue that couples front and backend processing
        self.q = Queue.Queue(maxsize=4*1024)

        # create a single entry thread pool to offload callbacks
        self.dispatcher_thread = threading.Thread(
                target=self.dispatcher,
                name='{0}-dispatcher'.format(PROCESS_NAME))

        self.log.info('start dispatcher')
        self.dispatcher_thread.start()

        # connect to CM to start the process
        self.initCM()

        self.log.info('wait forever')
        self.dispatcher_thread.join()

        self.log.info('Process exit. this should not happen')

    # EXOS interface
    def initCM(self):
        # Connect to CM as an EPM process
        self.log.debug('Called')

        # this is the CM callback when we startup
        class StpCmAgent(CmAgent):
            def __init__(self, q, logger, callback):
                logger.info('Called')
                super(StpCmAgent, self).__init__()
                self.q = q
                self.log = logger
                self.callback = callback

            def event_generate_default(self):
                self.log.info('Called')
                self.q.put((self.callback,))

        cmbackend_init(StpCmAgent(self.q, self.log, self.after_cm_startup_main))

    def dispatcher(self):
        # this is the main dispatcher thread for backend functions
        while True:
            # queue entries are function followed by optional args
            try:
                dspatch = self.q.get(timeout=30)
            except Queue.Empty:
                self.log.debug('queue empty, polling for vlans')
                self.cli_callback()
                continue
            it = iter(dspatch)
            func = it.next()
            params = list(it)
            try:
                func(*params)
            except Exception as msg:
                self.log.debug(msg)
        self.log.info('Exit')

    def after_cm_startup_main(self):
        # This function is given its own thread after CM startup is complete
        # After EXOS process init is completed. Start our vlan to stp mapping
        # process
        self.log.debug('Called')
        ready()
        vlan.notify.vlan_create.add_observer(self.vlan_create)

    def exos_cmd(self, cmd=[]):
        for line in cmd:
            self.log.info(line)
        reply = exec_cli(cmd, ignore_errors=True)
        self.log.info(reply)
        return reply

    def vlan_create(self, *args, **kwargs):
        # EXOS callback when a VLAN is added
        self.log.info('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        if vlan_name is None:
            self.log.info('Did not find {vname}'.format(XDB.VPC.NAME))
            # shouldn't happen
            return
        self.q.put((self.do_exos_add, vlan_name))

    def do_exos_add(self, vlan_name):
        # Running in its own thread to offload EXOS callback, Add vlan to stp 's0'
        self.log.info('Called with {0}'.format(vlan_name))

        cmd = []
        cmd.append('config stpd {stp_name} add vlan {vname} ports all'.format(
            vname=vlan_name, stp_name=XDB.DEFAULT_STP_NAME))
        cmd.append('enable stpd {stp_name} auto-bind vlan {vname}'.format(
            vname=vlan_name, stp_name=XDB.DEFAULT_STP_NAME))
        self.exos_cmd(cmd)

    def cli_callback(self):
        self.log.debug('Called')
        # periodically poll to see if there are new vlans
        cmd = 'debug cfgmgr show next vlan.vlanMap vlanList=None vlanId=None'
        self.vlan_stp_dict = self.build_vlan_stp_db()
        exec_cli_async([cmd], self.vlan_map)

    def vlan_map(self, reply_done, reply):
        # VLAN MAP
        # compare map against last map looking for new entries
        if reply_done == CLI_EVENT_EXEC_REPLY:
            # collect parts of the CLI reply and aggregate them ehre
            self.cli_reply.append(reply)
            return

        # Turn the cli JSON into a dictionary
        reply_dict = json.loads(''.join(self.cli_reply))

        self.cli_reply = []
        reply_set = set()

        # go through the vlanMap entries and build a set of existing (VID, VNAME)
        for row in reply_dict.get('data'):
            vlanId = row.get('vlanId')
            vlanName = row.get('vlanName')
            if vlanId is None or vlanName is None:
                continue
            reply_set.add((vlanId, vlanName))
        self.log.debug(reply_set)

        # compute the difference between the current set of (VID, VNAME) and the previous one
        new_vlan_set = reply_set.difference(self.vlan_map_set)

        # store the current set for the next time
        self.vlan_map_set = reply_set

        if new_vlan_set:
            self.log.info('change set:{0}'.format(new_vlan_set))
        # for each new vlan, queue it to be added to s0 in a background thread
        for (vlanId, vlanName) in new_vlan_set:
            # check if new vlan is already attached to a spanning tree
            stp_name = self.vlan_stp_dict.get(vlanName)
            if stp_name is None:
                self.q.put((self.do_exos_add, vlanName))



################################################################################
# EXPY starting before 21.1
#
class EzStpdExpyPre21(EzStpdBase):
    def __init__(self):
        super(EzStpdExpyPre21, self).__init__()

        # root logger
        self.rlog = logging.getLogger('')
        self.rlog.setLevel(logging.INFO)
        self.logHandler = TraceBufferHandler("rlog", 20480)
        self.logHandler.setLevel(logging.INFO)
        self.logHandler.setFormatter(logging.Formatter(
            "%(name)05s:%(funcName)s.%(lineno)s:: %(message)s"))
        if not len(self.rlog.handlers):
            self.rlog.addHandler(self.logHandler)

        # threads
        self.dispatcher_thread = None
        self.q = None

        self.cli_reply = []
        self.vlan_map_set = set()
        self.vlan_stp_dict = None

    def __call__(self):
        # expy process main

        # create the queue that couples front and backend processing
        self.q = Queue.Queue(maxsize=4*1024)

        # create a single entry thread pool to offload callbacks
        self.dispatcher_thread = threading.Thread(
                target=self.dispatcher,
                name='{0}-dispatcher'.format(PROCESS_NAME))

        self.log.info('start dispatcher')
        self.dispatcher_thread.start()

        # connect to CM to start the process
        self.initCM()

        self.log.info('wait forever')
        self.dispatcher_thread.join()

        self.log.info('Process exit. this should not happen')

    # EXOS interface
    def initCM(self):
        # Connect to CM as an EPM process
        self.log.debug('Called')
        cmd = 'debug cfgmgr show next vlan.vlanMap vlanList=None vlanId=None'

        # periodically poll to see if there are new vlans
        while True:
            self.vlan_stp_dict = self.build_vlan_stp_db()

            exec_cli_async([cmd], self.vlan_map)
            time.sleep(30)

    def vlan_map(self, reply_done, reply):
        # VLAN MAP
        # compare map against last map looking for new entries
        if reply_done == CLI_EVENT_EXEC_REPLY:
            # collect parts of the CLI reply and aggregate them ehre
            self.cli_reply.append(reply)
            return

        # Turn the cli JSON into a dictionary
        reply_dict = json.loads(''.join(self.cli_reply))

        self.cli_reply = []
        reply_set = set()

        # go through the vlanMap entries and build a set of existing (VID, VNAME)
        for row in reply_dict.get('data'):
            vlanId = row.get('vlanId')
            vlanName = row.get('vlanName')
            if vlanId is None or vlanName is None:
                continue
            reply_set.add((vlanId, vlanName))
        self.log.debug(reply_set)

        # compute the difference between the current set of (VID, VNAME) and the previous one
        new_vlan_set = reply_set.difference(self.vlan_map_set)

        # store the current set for the next time
        self.vlan_map_set = reply_set

        if new_vlan_set:
            self.log.info('change set:{0}'.format(new_vlan_set))
        # for each new vlan, queue it to be added to s0 in a background thread
        for (vlanId, vlanName) in new_vlan_set:
            # check if new vlan is already attached to a spanning tree
            stp_name = self.vlan_stp_dict.get(vlanName)
            if stp_name is None:
                self.q.put((self.do_exos_add, vlanName))

    def dispatcher(self):
        # this is the main dispatcher thread for backend functions
        while True:
            # queue entries are function followed by optional args
            dspatch = self.q.get()
            it = iter(dspatch)
            func = it.next()
            params = list(it)
            try:
                func(*params)
            except Exception as msg:
                self.log.warn(msg)
        self.log.info('Exit')

    def exos_cmd(self, cmd=[]):
        for line in cmd:
            self.log.info(line)
        exec_cli(cmd, ignore_errors=True)

    def do_exos_add(self, vlan_name):
        # Running in its own thread to offload EXOS callback, Add vlan to stp 's0'
        self.log.info('Called with {0}'.format(vlan_name))

        cmd = []
        cmd.append('config stpd {stp_name} add vlan {vname} ports all'.format(
            vname=vlan_name, stp_name=XDB.DEFAULT_STP_NAME))
        cmd.append('enable stpd {stp_name} auto-bind vlan {vname}'.format(
            vname=vlan_name, stp_name=XDB.DEFAULT_STP_NAME))
        self.exos_cmd(cmd)


# decide which context we running in, then call the correct class
# CLI invokes the EzStpdCli() class within the CLI action
if __name__ == '__main__':
    if i_am_script is True:
        a = EzStpdScript()
        a()
    elif i_am_expy is True:
        if i_am_exos_pre21 is True:
            a = EzStpdExpyPre21()
        else:
            a = EzStpdExpy()
        a()
