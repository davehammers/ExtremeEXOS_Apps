# ******************************************************
#
#  Copyright (c) Extreme Networks Inc. 2016
#  All rights reserved
#
# ******************************************************
'''
This application uses the Broadcom shell cable diagnostic capability
to show users the health of the cable connected to wired ports (i.e. not fiber)

The output of several EXOS and Broadcom commands are captured and
combined to form the output.

    debug hal run platform portmap
        Collect the EXOS port to Broadcom unit/port mapping
    jerry hal platform bcm-cmd slot <slot> unit <unit> "phy info"
        Collect the broadcom port name to broadcom unit/port mapping
    jerry hal platform bcm-cmd slot <slot> unit <unit> "cablediag <bcmPortName>"
        Perform the cable diagnostics on the named port

Output displays EXOS port numbers.

If this is run in a stacking environment, the slot number is printed
before each group of ports.

Fiber ports do not return output.

'''
import os
import os.path
import sys
import socket
import argparse
import logging
import threading
from time import sleep

__version__ = '1.1.0.4'
# --------------------------------------------------
#   1.1.0.4
# xos0072618 - Do not prompt for yes/no confirmation
# --------------------------------------------------
#   1.1.0.3
# accept s:p format for ports
# --------------------------------------------------
#   1.1.0.2
#   3-Jan-2017
# fixes for X870

# --------------------------------------------------
#   1.1.0.1
#   2-Nov-2016
# refactor to provide REST api interface

# --------------------------------------------------
#   1.0.0.3
#   14-Sep-2015
# Skip Stack links
#   CABLEdiag: stacking link: port 31: Feature unavailable

# --------------------------------------------------
#   1.0.0.2
#
# Display caution message:
#   will momentarily interfere with traffic on active ports

# --------------------------------------------------
#   1.0.0.1
#
# Initial release in 21.1.2

try:
    import json
    import exsh
    i_am_script = True
except:
    from exos.api import exos_dbapi as dbapi
    from exos.api import exec_cli
    import pprint
    i_am_script = False


# **********************************************************************
# C O N S T A N T S
# **********************************************************************
class XosDB(object):
    PROCESS_NAME = os.path.splitext(os.path.basename(__file__))[0]
    SOCKET_NAME = '/tmp/cablediag'
    SLOT = 'slot'  # consistent spelling of slot/port
    PORT = 'port'
    RESULT = 'result'

    LOGIN = 'admin'

    class Method(object):
        SHOW = 'show'
    METHOD = Method()

    class Hal(object):
        MODULE = 'hal'

        class HalPlatformDebug(object):
            BLOCK = 'halPlatCLIDebug'

            COMMAND = 'command'
            COMMAND2 = 'command2'
            DEVICE = 'device'
            WHAT = 'what'
            PARM1 = 'parm1'
            PARM2 = 'parm2'
            PARM3 = 'parm3'
            PARM4 = 'parm4'
            PARM5 = 'parm5'
            PARM6 = 'parm6'
            PARM7 = 'parm7'
            PARM8 = 'parm8'
            STRING1 = 'string1'
            STRING2 = 'string2'
            STRING3 = 'string3'
            STRING4 = 'string4'
        DEBUG = HalPlatformDebug()

        class StackingShowInfo(object):
            BLOCK = 'stackingShowInfo'

            DATA = 'data'

            IS_MASTER = 'host_is_master'

        STK_INFO = StackingShowInfo()

    HAL = Hal()

    class Dm(object):
        MODULE = 'dm'

        class CardInfo(object):
            BLOCK = 'card_info'

            SLOT = 'slot'
            PORTS = 'ports'
            CARD_NAME = 'card_name'
            CARD_STATE = 'card_state'
            CARD_STATE_DESC = 'card_state_str'
            CARD_TYPE = 'card_type'

        CARD = CardInfo()

    DM = Dm()

    class Vlan(object):
        MODULE = 'vlan'

        class ShowPortsInfo(object):
            BLOCK = 'show_ports_info'

            DATA = 'data'
            PORTLIST = 'portList'
        SHOW_PORT = ShowPortsInfo()
    VLAN = Vlan()

    class Epm(object):
        MODULE = 'epm'

        class Epmpcb(object):
            BLOCK = 'epmpcb'

            DATA = 'data'
            NAME = 'name'
            PID = 'pid'
        PCB = Epmpcb()
    EPM = Epm()

XDB = XosDB()

cdiag_handle = logging.StreamHandler(sys.stderr)
cdiag_handle.setLevel(logging.INFO)
cdiag_handle.setFormatter(logging.Formatter(
    '%(levelname)s:%(threadName)s:%(name)s:%(funcName)s.%(lineno)s:: '
    '%(message)s'))
cdiag_log = logging.getLogger(XDB.PROCESS_NAME)
cdiag_log.setLevel(logging.INFO)
if not len(cdiag_log.handlers):
    cdiag_log.addHandler(cdiag_handle)


# **********************************************************************
# This is a common class of arg parsing for both script and expy env
# **********************************************************************
class CableArgs(object):
    'this class is shared by both run script context and expy context'

    def get_params(self):
        parser = argparse.ArgumentParser(prog=XDB.PROCESS_NAME)
        parser.add_argument(
            '-p', '--portList',
            help='Port list separated by a "," or "-"',
            nargs='+',
            default=None)
        parser.add_argument(
            '-f', '--force',
            help='Do not prompt for confirmation when running {}'.format(XDB.PROCESS_NAME),
            action='store_true',
            default=False)
        parser.add_argument(
            '-d', '--debug',
            help='Enable debug',
            action='store_true',
            dest='debug',
            default=False)
        args = parser.parse_args()
        if args.debug:
            cdiag_handle.setLevel(logging.DEBUG)
            cdiag_log.setLevel(logging.DEBUG)
        cdiag_log.debug(args)

        return args

def exos_clicmd(cmd):
    cdiag_log.debug('CMD:{0}'.format(cmd))
    reply = exsh.clicmd(cmd, capture=True)
    cdiag_log.debug('REPLY:{0}'.format(reply))
    return reply

#*******************************************************************
# This class is used to extract slots & ports from portlist_t string
# function arguments = string
#*******************************************************************
class portList(object):

    # class slotPort maintains slot number and list of ports specified
    # for that slot
    class slotPort:
        slot = 0
        ports = []

    def __init__(self):
        # self.portList will have the list of the objects of type
        # class slotPort.
        self.portList = []
        self.max_port = None
        self.stack_mode = None
        self.available_portList = None

    # This is used to get the max_port for specific slot for both case
    # running as script or process which is decided by "i_am_script" variable.
    # (Here slot = string).
    def get_max_port_by_slot(self, slot):
        end_port = None
        cmd = 'debug cfgmgr show one vlan.show_ports_info portList=*'
        if i_am_script == True:
            reply = exos_clicmd(cmd)
        else:
            reply = exec_cli([cmd])
        try:
            data = json.loads(reply)
            block = data[XDB.VLAN.SHOW_PORT.DATA][0]
            cdiag_log.debug(json.dumps(block, indent=2))
            # This will give available port range for available slots in form of
            # i) for stand alone,
            #       begin_port-end_port
            # ii) for stacking,
            #       slot_1:begin_port-end_port,slot_2:begin_port-end_port,...
            self.available_portlist = block[XDB.VLAN.SHOW_PORT.PORTLIST]
        except:
            return -1
        # Extrct the max_port for required slot from the port range got above
        slot_groups = self.available_portlist.split(',')
        if ':' not in self.available_portlist:
            # Stand alone mode - begin_port-end_port
            begin_port, sep, end_port = slot_groups[0].partition('-')
            cdiag_log.debug('{0} {1} {2}'.format(begin_port, sep, end_port))
        else:
            # Stacking mode - slot:begin_port-end_port
            cdiag_log.debug(slot_groups)
            index = 0
            for slot_group in slot_groups:
                slot_num, port_range = slot_group.split(':')
                if slot_num == slot:
                    begin_port, sep, end_port = slot_group.partition('-')
                    cdiag_log.debug('{0} {1} {2}'.format(begin_port, sep, end_port))
                    break
                index += 1
            if index == len(slot_groups):
                # Slot not found
                return 0
        cdiag_log.debug('Max port number is {0}'.format(end_port))
        return end_port


    # This function returns list of ports for range between start_port and
    # end_port or single port if end_port is None.
    # All arguments = string
    def expand_port_range(self, start_port, end_port, max_port):
        if (start_port is None or not start_port.isdigit() or
                int(start_port) < 1 or int(start_port) > int(max_port)):
            return None
        if end_port is not None:
            if (not end_port.isdigit() or int(end_port) < 1 or
                 int(end_port) > int(max_port) or int(start_port) > int(end_port)):
                return None
            return list(range(int(start_port), int(end_port)+1))
        else:
            return [int(start_port)]

    #***************************************************************#
    # Func: def extract_ports_from_portlist(self, portList_string)  #
    #                                                               #
    # portList_string is string of port list for stand alone and    #
    # string of slot:port port list for stack received by           #
    # portlist_t type from CLI                                      #
    #                                                               #
    # This function returns list of objects of type class slotPort. #
    #                                                               #
    # Object of class slotPort will have the slot number and list   #
    # of ports specified for that slot.                             #
    #   class slotPort():                                           #
    #       slot  # slot number                                     #
    #       ports # list of ports for this slot number              #
    #                                                               #
    #***************************************************************#
    def extract_ports_from_portlist(self, portList_string):

        while portList_string.find('  ') != -1:
            portList_string = portList_string.replace('  ', ' ')
        portList_string = portList_string.replace(' ,', ',')
        portList_string = portList_string.replace(', ', ',')
        portList_string = portList_string.replace(' -', '-')
        portList_string = portList_string.replace('- ', '-')
        portList_string = portList_string.replace(' ', ',')

        self.stack_mode = os.getenv('EXOS_STACK_MODE', '0')
        if self.stack_mode == '1':
            #stack-mode
            port_ranges = portList_string.split(',')
            for port_range in port_ranges:
                if port_range.find('*') != -1:
                    # All ports case
                    all_ports = port_range.split(':')
                    if len(all_ports) == 2:
                        slot = all_ports[0]
                    if (len(all_ports) != 2 or not slot.isdigit() or all_ports[1] != '*'):
                        raise ValueError ('Error:port_range {} is invalid'.format(port_range))
                    self.max_port = self.get_max_port_by_slot(slot)
                    if self.max_port == -1:
                        raise ValueError ('Error while getting the max port for slot {}'.format(slot))
                    elif self.max_port == 0:
                        raise ValueError ('Error:Slot {} is not present'.format(slot))
                    else:
                        pass
                    port_range = port_range.replace('*','1-{}'.format(self.max_port))
                slot_port = port_range.split('-')
                start_slot_port = slot_port[0].split(':')
                if len(slot_port) > 2 or len(start_slot_port) != 2:
                    raise ValueError ('Error:port_range {} is invalid'.format(port_range))
                start_slot = start_slot_port[0]
                start_port = start_slot_port[1]
                if not start_slot.isdigit():
                    raise ValueError('Error:Port {} is invalid'.format(port_range))
                if len(slot_port) == 1:
                    #Single port case
                    self.max_port = self.get_max_port_by_slot(start_slot)
                    if self.max_port == -1:
                        raise ValueError ('Error while getting the max port for slot {}'.format(slot))
                    elif self.max_port == 0:
                        raise ValueError ('Error:Slot {} is not present'.format(slot))
                    else:
                        pass
                    ports = self.expand_port_range(start_port, None, self.max_port)
                    if ports is None:
                        raise ValueError ('Error:Port {} is Invalid'.format(port_range))
                    index = 0
                    for slotPort_instance in self.portList:
                        if slotPort_instance.slot == int(start_slot):
                            break
                        index += 1
                    if index == len(self.portList):
                        self.portList.append(portList.slotPort())
                        self.portList[index].slot = int(start_slot)
                        self.portList[index].ports = []
                    self.portList[index].ports += ports
                    continue
                else:
                    #Port range case
                    end_slot_port = slot_port[1].split(':')
                    if len(end_slot_port) == 1:
                        #single slot port range case
                        end_slot = start_slot
                        end_port = end_slot_port[0]
                    elif len(end_slot_port) == 2:
                        #May have multiple slots - port range case
                        end_slot = end_slot_port[0]
                        end_port = end_slot_port[1]
                        if (not end_slot.isdigit() or int(end_slot) < int(start_slot)):
                            raise ValueError('Error:Port {} is invalid'.format(port_range))
                    else:
                        raise ValueError ('Error:port_range {} is invalid'.format(port_range))
                if start_slot == end_slot:
                    #Single slot- port range case
                    self.max_port = self.get_max_port_by_slot(start_slot)
                    if self.max_port == -1:
                        raise ValueError ('Error in getting the max port for slot {}'.format(slot))
                    elif self.max_port == 0:
                        raise ValueError ('Error:Slot {} is not present'.format(slot))
                    else:
                        pass
                    ports = self.expand_port_range(start_port, end_port, self.max_port)
                    if ports is None:
                        raise ValueError ('Error:Port range {} is Invalid'.format(port_range))
                    index = 0
                    for slotPort_instance in self.portList:
                        if slotPort_instance.slot == int(start_slot):
                            break
                        index += 1
                    if index == len(self.portList):
                        self.portList.append(portList.slotPort())
                        self.portList[index].slot = int(start_slot)
                        self.portList[index].ports = []
                    self.portList[index].ports += ports
                else:
                    # multiple slot- port range case
                    for slot in range(int(start_slot), int(end_slot) + 1):
                        self.max_port = self.get_max_port_by_slot(str(slot))
                        if self.max_port == -1:
                            raise ValueError ('Error in getting the max port for slot {}'.format(slot))
                        elif self.max_port == 0:
                            raise ValueError ('Error:Slot {} is not present'.format(slot))
                        else:
                            pass
                        if slot == int(start_slot):
                            ports = self.expand_port_range(start_port, self.max_port, self.max_port)
                        elif slot == int(end_slot):
                            ports = self.expand_port_range('1', end_port, self.max_port)
                        else:
                            ports = self.expand_port_range('1', self.max_port, self. max_port)
                        if ports is None:
                            raise ValueError ('Error:Port range {} is Invalid'.format(port_range))
                        index = 0
                        for slotPort_instance in self.portList:
                            if slotPort_instance.slot == slot:
                                break
                            index += 1
                        if index == len(self.portList):
                            self.portList.append(portList.slotPort())
                            self.portList[index].slot = slot
                            self.portList[index].ports = []
                        self.portList[index].ports += ports
            for slotPort_instance in self.portList:
                slotPort_instance.ports = sorted(set(slotPort_instance.ports), key=int)
        else:
            #stand alone
            port_list = portList_string.split(',')
            self.max_port = self.get_max_port_by_slot('1')
            if self.max_port == -1:
                raise ValueError ('Error in getting the max port for slot {}'.format(slot))
            elif self.max_port == 0:
                raise ValueError ('Error:Slot {} is not present'.format(slot))
            else:
                pass
            for port_range in port_list:
                slot_port = port_range.split('-')
                start_port = slot_port[0]
                if len(slot_port) == 1:
                    #Single port case
                    end_port = None
                elif len(slot_port) == 2:
                    #Port range case
                    end_port = slot_port[1]
                else:
                    raise ValueError ('Error:Port {} is invalid'.format(port_range))
                ports = self.expand_port_range(start_port, end_port, self.max_port)
                if ports is None:
                    raise ValueError ('Error:Port {} is Invalid'.format(port_range))
                if len(self.portList) == 0:
                    self.portList.append(portList.slotPort())
                    self.portList[0].slot = 1
                    self.portList[0].ports = []
                self.portList[0].ports += ports
            self.portList[0].ports = sorted(set(self.portList[0].ports), key=int)
        return self.portList


# **********************************************************************
# This is the base Expy context class that can be invoked from
# REST or EXOS start process
# **********************************************************************
class ExpyCableDiagBase(CableArgs):

    def __init__(self):
        super(ExpyCableDiagBase, self).__init__()

        self.portList = None
        self.stack_mode = None
        self.print_realtime = None
        self.save_slot = None
        self.answer = []

    # This method accepts an optional list of portList
    # input:
    #   portList_string - Port list separated by a "," or "-".
    #   e.g. for stand alone, 1,2,5 or 5-8 or combination 1,2,5-8
    #   for stacking, 1:1,1:2,2:5 or 1:1-10,2:4-2:6 or combination 1:1,1:2,2:5,2:3-3:7
    #           None == all slots:all ports
    #
    # It returns a list of
    # [
    #   {
    #       slot : integer,
    #       port : integer,
    #       result : string, (Broadcom shell output)
    #   }
    # ]

    def __call__(self, portList_string=None, stacking=None, print_realtime=None):
        self.stack_mode = stacking
        self.print_realtime = print_realtime

        if portList_string is not None:
            cdiag_log.debug(portList_string)
            portList_string = ' '.join(portList_string)
            try:
                self.portList = portList().extract_ports_from_portlist(portList_string)
            except Exception as msg:
                print msg
                print ('usage: cablediag [-h] [-p PORTLIST [PORTLIST ...]] [-f] [-d]\n')
                self.stack_mode = os.getenv('EXOS_STACK_MODE', '0')
                if self.stack_mode == '1':
                    print ('Port list can only be defined by ports separated by "," or "-".\n'
                    'e.g. 1:1,2:4 or 1:1-10 or 2:30-3:5 or combination of all')
                else:
                    print ('Port list can only be defined by ports separated by "," or "-".\n'
                    'e.g. 1,2,3 or 4-9 or combination 1,4,7,10-15.. etc')
                return

        # build a translation map between EXOS and broadcom port mappings
        bcm_to_exos_port_map, exos_to_bcm_port_map = self._build_bcm_to_exos_port_map()
        cdiag_log.debug('bcm_to_exos_port_map=\n{0}'.format(
            pprint.pformat(bcm_to_exos_port_map, indent=4)))
        cdiag_log.debug('exos_to_bcm_port_map=\n{0}'.format(
            pprint.pformat(exos_to_bcm_port_map, indent=4)))

        # check if the request has slots that are not present in the system
        if self.portList is not None:
            for slotPort_instance in self.portList:
                if slotPort_instance.slot not in exos_to_bcm_port_map:
                    self._add_to_answer(slot, None, 'Slot {0} is not '
                        'present'.format(slotPort_instance.slot))
                    return self.answer

        # walk through each slot in the exos map
        for slot in sorted(exos_to_bcm_port_map.keys()):
            # check if the command line has specific slots
            if self.portList is not None:
                index = 0
                for slotPort_instance in self.portList:
                    if slotPort_instance.slot == slot:
                        # slot is specified in command line
                        break
                    index += 1
                if index == len(self.portList):
                    # slot not specified in the command line
                    continue

            # Walk through the units for a slot getting the diagnostics
            bcm_name_to_port_map = {}
            bcm_port_to_name_map = {}
            for unit in sorted(bcm_to_exos_port_map[slot].keys()):
                # get a mapping of brcm port names to chip port numbers e.g. ge2 -> 7
                self._build_bcm_name_to_port_map(
                    slot,
                    unit,
                    bcm_name_to_port_map,
                    bcm_port_to_name_map)

            cdiag_log.debug('bcm_name_to_port_map=\n{0}'.format(
                pprint.pformat(bcm_name_to_port_map, indent=4)))
            cdiag_log.debug('bcm_port_to_name_map=\n{0}'.format(
                pprint.pformat(bcm_port_to_name_map, indent=4)))

            if len(bcm_name_to_port_map) == 0 or len(bcm_port_to_name_map) == 0:
                # there were no port mapping results
                continue

            # walk through each EXOS port number in order
            if self.portList is None:
                cdiag_log.debug(self.portList)
            else:
                cdiag_log.debug(slotPort_instance.slot)

            for exos_port in sorted(exos_to_bcm_port_map[slot].keys()):
                # filter display to only the ones asked for
                if self.portList is None or exos_port in slotPort_instance.ports:
                    pass
                else:
                    # port not specified on the command line
                    continue

                # for an EXOS slot/port, find the broadcom slot/unit/port
                bcm_slot, bcm_unit, bcm_port = exos_to_bcm_port_map[slot].get(
                    exos_port,
                    (None, None, None))

                if bcm_slot is None or bcm_unit is None or bcm_port is None:
                    continue

                # translate the broadcom unit/portnum into unit/portname (e.g.) 50->xe6
                unit, bcm_port_name = bcm_port_to_name_map.get(
                    (bcm_unit, bcm_port),
                    (None, None))
                if unit is None or bcm_port_name is None:
                    continue

                cdiag_log.debug('slot={slot}, unit={unit}, port_name={port_name}'.format(
                    slot=slot,
                    unit=unit,
                    port_name=bcm_port_name))
                # run the cable diagnostics for that slot/unit
                diag_list = self._collect_diag(slot, unit, bcm_port_name)

                if diag_list is None:
                    # there were no diag results for this port
                    continue

                # print first line with bcm port name translated to EXOS port number
                if len(diag_list) == 0:
                    continue

                diag_list[0] = diag_list[0].replace(bcm_port_name, str(exos_port))
                self._add_to_answer(slot, exos_port, '\n'.join(diag_list))
        return self.answer

    def _add_to_answer(self, slot, port, result):
        self.answer.append({XDB.SLOT: slot or '', XDB.PORT: port or '', XDB.RESULT: result or ''})
        if self.print_realtime is True:
            # stacking mode. Print the slot heading
            if self.stack_mode == '1' and self.save_slot != slot:
                print 'Slot', slot
                self.save_slot = slot
            print result

    def _build_bcm_to_exos_port_map(self):
        'debug hal run platform portmap'

        # collect the debug response to run platform portmap
        def _hal_print_callback(msg):
            _hal_print_callback.answer += msg
        _hal_print_callback.answer = ''

        cm_conn = dbapi.connect(XDB.LOGIN, print_callback=_hal_print_callback)
        cursor = cm_conn.cursor()
        req = dbapi.request()

        # Index field
        req.method = XDB.METHOD.SHOW

        # additional parameters
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND), 'portmap')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND2), 'debug')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.WHAT), 1)

        cursor.execute(req)
        cursor.fetchrow()

# The function below scrapes the data out of the debug response
# debug hal run platform portmap
#
#        Slot: 1  CardType: X440G2-48t-10G4
#           ModId Unit(G/L) PIQ     Ports (FrontPanelPort - PIQPort)
#             0     1/0     xxxx-0   1-2   2-3   3-4   4-5   5-6   6-7
#                                     7-8   8-9   9-10 10-11 11-12 12-13
#                                    13-14 14-15 15-16 16-17 17-18 18-19
#                                    19-20 20-21 21-22 22-23 23-24 24-25
#
#             2     2/1     xxxx-1  25-2  26-3  27-4  28-5  29-6  30-7
#                                    31-8  32-9  33-10 34-11 35-12 36-13
#                                    37-14 38-15 39-16 40-17 41-18 42-19
#                                    43-20 44-21 45-22 46-23 47-24 48-25
#                                    49-26 50-27
#             0     1/0     xxxx-0  51-29 52-28
#        Slot: 2  CardType: X620-16t
#           ModId Unit(G/L) PIQ     Ports (FrontPanelPort - PIQPort)
#             4     9/0     xxxx-0   1-3   2-2   3-5   4-4   5-7   6-6
#                                     7-9   8-8   9-11 10-10 11-13 12-12
#                                    13-15 14-14 15-17 16-16
#        Slot: 3  CardType: X440G2-12t-10G4
#           ModId Unit(G/L) PIQ     Ports (FrontPanelPort - PIQPort)
#             8    17/0     xxxx-0   1-2   2-3   3-4   4-5   5-6   6-7
#                                     7-8   8-9   9-10 10-11 11-12 12-13
#                                    13-27 14-26 15-28 16-29
#        Slot: 4  CardType: X620-10x
#           ModId Unit(G/L) PIQ     Ports (FrontPanelPort - PIQPort)
#            12    25/0     xxxx-0   1-2   2-3   3-4   4-5   5-6   6-7
#                                     7-8   8-9   9-10 10-11

        # put the port numbers back together in a string
        lines = _hal_print_callback.answer.splitlines()

        # walk through the lines and extract the port mapping groups
        bcm_to_exos_port_map = dict(dict(dict()))
        exos_to_bcm_port_map = dict(dict())
        for line in lines:
            l = line.lstrip()

            if len(l) == 0:
                continue

            if l.startswith('Slot'):
                # parts out slot number
                slot = l.split()[1]
                continue

            if l.startswith('ModId'):
                # Heading line
                continue

            token = l.split()

            # for each port pair, extract the exos and broadcom port numbers
            for port in token:
                if '/' in port:
                    bcm_global_unit, sep, bcm_unit = port.partition('/')
                    continue

                # look for port pairs exos-bcm
                exos_port, sep, bcm_port = port.partition('-')
                if sep != '-':
                    continue

                if exos_port == 'xxxx':
                    continue
                if int(exos_port) > 500:
                    continue

                unit_dict = bcm_to_exos_port_map.setdefault(int(slot), {})
                port_dict = unit_dict.setdefault(int(bcm_unit), {})
                port_dict.setdefault(int(bcm_port), int(exos_port))

                exos_port_dict = exos_to_bcm_port_map.setdefault(int(slot), {})
                exos_port_dict.setdefault(
                    int(exos_port), (int(slot), int(bcm_unit), int(bcm_port)))

        return bcm_to_exos_port_map, exos_to_bcm_port_map

    def _build_bcm_name_to_port_map(self, slot, unit, bcm_name_to_port_map, bcm_port_to_name_map):
        'jerry hal platform bcm-cmd slot <slot> unit <unit> "phy info"'

        # collect the bcm shell response to phy info
        def _hal_print_callback(msg):
            _hal_print_callback.answer += msg
        _hal_print_callback.answer = ''

        cm_conn = dbapi.connect(XDB.LOGIN, print_callback=_hal_print_callback)
        cursor = cm_conn.cursor()
        req = dbapi.request()

        # Index field
        req.method = XDB.METHOD.SHOW

        # additional parameters
        # req.add_param(dbapi.Column(
        # (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND), 'help')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND2), 'debug')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.DEVICE), 3)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.WHAT), 11)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.PARM1), slot)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.PARM2), unit)
        # dummy command to get the shell started
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.STRING1), 'phy info')

        cursor.execute(req)
        cursor.fetchrow()
#        Phy mapping dump:
#             port   id0   id1  addr iaddr                    name           timeout
#         ge0(  1)  600d  8443     9    89                BCM54280     250000
#         ge1(  2)  600d  8443     a    8a                BCM54280     250000
#         ge2(  3)  600d  8443     b    8b                BCM54280     250000
#         ge3(  4)  600d  8443     c    8c                BCM54280     250000
#         ge4(  5)  600d  8443     d    8d                BCM54280     250000
#         ge5(  6)  600d  8443     e    8e                BCM54280     250000
#         ge6(  7)  600d  8443     f    8f                BCM54280     250000
#         ge7(  8)  600d  8443    10    90                BCM54280     250000
#         ge8(  9)  600d  8443    11    91                BCM54280     250000
#         ge9( 10)  600d  8443    12    92                BCM54280     250000
#        ge10( 11)  600d  8443    13    93                BCM54280     250000
#        ge11( 12)  600d  8443    14    94                BCM54280     250000
#        ge12( 13)  600d  8443    15    95                BCM54280     250000
#        ge13( 14)  600d  8443    16    96                BCM54280     250000
#        ge14( 15)  600d  8443    17    97                BCM54280     250000
#        ge15( 16)  600d  8443    18    98                BCM54280     250000
#        ge16( 17)  600d  8463    21    99                BCM54240     250000
#        ge17( 18)  600d  8463    22    9a                BCM54240     250000
#        ge18( 19)  600d  8463    23    9b                BCM54240     250000
#        ge19( 20)  600d  8463    24    9c                BCM54240     250000
#        ge20( 21)  600d  8463    25    a1                BCM54240     250000
#        ge21( 22)  600d  8463    26    a2                BCM54240     250000
#        ge22( 23)  600d  8463    27    a3                BCM54240     250000
#        ge23( 24)  600d  8463    28    a4                BCM54240     250000
#        ge24( 25)   143  bff0    a5    a5         XGXS13G-B0/02/0     250000
#        ge25( 26)   143  bff0    a6    a6         XGXS13G-B0/02/1     250000
#        ge26( 27)   143  bff0    a7    a7         XGXS13G-B0/02/2     250000
#        ge27( 28)   143  bff0    a8    a8         XGXS13G-B0/02/3     250000
#         xe0( 50)   143  bff0    c5    c5              WC-C1/01/0     250000
#         xe1( 51)   143  bff0    c5    c5              WC-C1/01/1     250000
#         xe2( 52)   143  bff0    c5    c5              WC-C1/01/2     250000
#         xe3( 53)   143  bff0    c5    c5              WC-C1/01/3     250000
#         xe4( 54)   143  bff0    d5    d5              WC-C1/05/4     250000
#         xe5( 55)   143  bff0    d9    d9              WC-C1/06/4     250000

        lines = _hal_print_callback.answer.splitlines()
        cdiag_log.debug(pprint.pformat(lines, indent=4))

        # build translation maps between Broadcom names and broadcom ports
        for line in lines:
            if '(' not in line:
                continue
            line = line.replace('(', ' ')
            line = line.replace(')', ' ')
            token = line.split()
            cdiag_log.debug('token: {}'.format(token))
            bcm_name_to_port_map[(unit, token[0])] = (unit, int(token[1]))
            bcm_port_to_name_map[(unit, int(token[1]))] = (unit, token[0])

        return

    def _collect_diag(self, slot, unit, bcm_port_name):
        'jerry hal platform bcm-cmd slot <slot> unit <unit> "cablediag <bcmPortName>"'

        # Collect cablediag for a bcm port name
        def _hal_print_callback(msg):
            _hal_print_callback.answer += msg
            cdiag_log.debug(msg)
        _hal_print_callback.answer = ''

        if bcm_port_name.startswith('hg'):
            return ['CABLEdiag: stacking link: port {0}: Feature unavailable'.format(
                bcm_port_name)]

        cm_conn = dbapi.connect(XDB.LOGIN, print_callback=_hal_print_callback)
        cursor = cm_conn.cursor()
        req = dbapi.request()

        # Index field
        req.method = XDB.METHOD.SHOW

        # additional parameters
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND), 'help')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.COMMAND2), 'debug')
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.DEVICE), 3)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.WHAT), 11)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.PARM1), slot)
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.PARM2), unit)
        # dummy command to get the shell started
        req.add_param(dbapi.Column(
            (XDB.HAL.MODULE, XDB.HAL.DEBUG.BLOCK), XDB.HAL.DEBUG.STRING1),
            'cablediag {0}'.format(bcm_port_name))

        cursor.execute(req)
        cursor.fetchrow()

#        port ge0: cable (4 pairs, length +/- 10 meters)
#                pair A Ok, length 0 meters
#                pair B Ok, length 0 meters
#                pair C Ok, length 0 meters
#                pair D Ok, length 0 meters

        # rebuild the list into a list of lines
        return _hal_print_callback.answer.splitlines()


# **********************************************************************
# This class is invoked via EXOS REST API
# **********************************************************************
class ExpyRESTCableDiag(CableArgs):
    def __call__(self, portList_string=None, debug=False):
        #   portList_string - Port list separated by a "," or "-"
        #                     None == all slots: all ports
        #
        if debug:
            sys.argv.append('-d')
        self.get_params()
        cd = ExpyCableDiagBase()
        return cd(portList_string, stacking=os.getenv('EXOS_STACK_MODE', '0'))


# **********************************************************************
# This class is invoked in the EXOS 'create process' expy context
# via the EXOS CLI: create process
# **********************************************************************
class ExpyProcessCableDiag(CableArgs):

    def __init__(self):
        super(ExpyProcessCableDiag, self).__init__()

        self.sock = None
        self.stack_mode = None

    def main(self):
        # Connect to the front end process with a private UNIX socket
        self.stack_mode = os.getenv('EXOS_STACK_MODE', '0')

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(XDB.SOCKET_NAME)
        except Exception as msg:
            print msg
            return

        # redirect stdout to the socket so simple print statments will go
        # to the front end
        sys.stdout = self.sock.makefile('w', 0)
        sys.stderr = sys.stdout

        args = self.get_params()

        cd = ExpyCableDiagBase()
        cd(args.portList, stacking=self.stack_mode, print_realtime=True)
        return


# **********************************************************************
# This class is invoked using the EXOS CLI: run script <script>
# **********************************************************************
class RunScriptCableDiag(CableArgs):
    def __init__(self):

        self.portList = None
        self.sock = None
        self.stack_mode = None
        self.arg = None

    def is_master(self):
        cmd = 'debug cfgmgr show one {module}.{block}'.format(
            module=XDB.HAL.MODULE, block=XDB.HAL.STK_INFO.BLOCK)
        reply = exos_clicmd(cmd)
        try:
            data = json.loads(reply)
            block = data[XDB.HAL.STK_INFO.DATA][0]
            cdiag_log.debug(json.dumps(block, indent=2))
            if block[XDB.HAL.STK_INFO.IS_MASTER] == '1':
                return True
        except:
            pass
        return False

    def warn_user(self):
        'Warn that cable diags will disrupt traffic on active ports'
        print
        msg = ['C A U T I O N', '{0} will momentarily interfere with traffic on active ports'.format(XDB.PROCESS_NAME)]

        if self.stack_mode == '1':
            if self.portList is not None:
                for slotPort_instance in self.portList:
                    slot_line = 'Slot {0}: '.format(slotPort_instance.slot)
                    slot_line += 'Ports: {0}'.format(','.join(str(x) for x in slotPort_instance.ports))
                    msg.append(slot_line)
            else:
                slot_line = 'All Slots: All Ports'
                msg.append(slot_line)
        else:
            if self.portList is not None:
                slot_line = 'Ports: {0}'.format(','.join(str(x) for x in self.portList[0].ports))
            else:
                slot_line = 'Ports: All Ports'
            msg.append(slot_line)

        self.display_box(msg, border='+')

        if self.args.force:
            return True

        while True:
            yes_no = raw_input('Do you want to continue cable diagnostics? [y/N]: ').strip().lower()
            cdiag_log.debug(yes_no)
            if yes_no not in ['', 'y', 'yes', 'n', 'no']:
                print 'unknown input', yes_no
                continue
            if len(yes_no) and yes_no[0] == 'y':
                return True
            return False

    @staticmethod
    def display_box(msg, border='*', width=None):
        if width is None:
            max_col = 0
            for l in msg:
                if len(l) > max_col:
                    max_col = len(l)
            max_col += 8
        else:
            max_col = width

        print border * max_col
        line = 0
        for l in msg:
            if line < 2:
                print '{border} {txt:^{col}} {border}'.format(border=border, txt=l, col=(max_col-4))
            if line == 2:
                print '{border}{sep}{border}'.format(border=border, sep='-' * (max_col-2))
            if line >= 2:
                spaces = max_col - (len(l) + 4)
                print '{border:4}{txt}{border:>{spaces}}'.format(border=border, txt=l, spaces=spaces)
            line += 1
        print border * max_col

    def process_cleanup(self):
        cmd = 'debug cfgmgr show one {module}.{block} {field}={proc}'.format(
            module=XDB.EPM.MODULE,
            block=XDB.EPM.PCB.BLOCK,
            field=XDB.EPM.PCB.NAME,
            proc=XDB.PROCESS_NAME)
        reply = exos_clicmd(cmd)
        try:
            data = json.loads(reply)
            cdiag_log.debug(json.dumps(data, indent=2))
            block = data[XDB.EPM.PCB.DATA][0]
            process_pid = block[XDB.EPM.PCB.PID]
        except:
            return

        if process_pid is None:
            cdiag_log.debug('No process to cleanup')
            return

        cdiag_log.debug('Found process. Need to cleanup first')

        # clean up any leftovers just in case
        # or possibly the command is already running on a second session
        try:
            exos_clicmd('delete process {0}'.format(XDB.PROCESS_NAME))
        except:
            pass

    def delayed_exos_cmd(self, delay_sec, cmd):
        sleep(delay_sec)
        exos_clicmd(cmd)

    def main(self):
        # process CLI parameters to validate them before calling the expy backend
        args = self.get_params()
        self.args = args

        if args.portList is not None:
            portList_string = ' '.join(args.portList)
            try:
                self.portList = portList().extract_ports_from_portlist(portList_string)
            except Exception as msg:
                print msg
                print ('usage: cablediag [-h] [-p PORTLIST [PORTLIST ...]] [-f] [-d]\n')
                self.stack_mode = os.getenv('EXOS_STACK_MODE', '0')
                if self.stack_mode == '1':
                    print ('Port list can only be defined by ports separated by "," or "-"\n'
                    'e.g. 1:1,2:4 or 1:1-10 or 2:30-3:5 or combination of all')
                else:
                    print ('Port list can only be defined by ports separated by "," or "-"\n'
                    'e.g. 1,2,3 or 4-9 or combination 1,4,7,10-15.. etc')
                return
            for slotPort_instance in self.portList:
                cdiag_log.debug(slotPort_instance.slot)
        else:
            self.portList = None

        self.sock = None
        self.stack_mode = os.getenv('EXOS_STACK_MODE', '0')

        print '{name}: {version}'.format(name=XDB.PROCESS_NAME, version=__version__)
        print

        # while we are still in the 'run script' context, check if we are master
        if self.is_master() is False:
            print 'Error: {0} can only run on the stack master'.format(XDB.PROCESS_NAME)
            return

        # cable diagnostics will disrupt traffic for a moment. Warn the User
        if self.warn_user() is not True:
            return

        print 'Collecting port cable diagnostic information may take a moment...'

        self.process_cleanup()
        # trim off the process name so that only CLI params are left
        del sys.argv[0]

        # reform the sys.argv in form of {-p "<portList_string>"} {-d} to limit
        # the number of arguments to pass while creating the process otherwise
        # in epm, comma separated ports will be considered as separate arguments
        # and if the number of port specifed are more than handled arguments
        # then epm may crash
        i = 0
        if len(sys.argv) > 0:
            if args.portList is not None:
                sys.argv[i] = '-p'
                sys.argv[i + 1] = '"{}"'.format(portList_string.replace(',', ' '))
                i += 2
            if args.debug is not False:
                sys.argv[i] = '-d'
                i += 1
        while i < len(sys.argv):
            del sys.argv[i]

        # create the EXOS expy backend process
        exos_clicmd('create process {0} python-module {0} start on-demand -- {1}'.format(
            XDB.PROCESS_NAME,
            ' '.join(sys.argv)))

        # the front end creates a UNIX socket server (i.e. a named pipe)
        # the backend will be the client and write to us
        try:
            os.remove(XDB.SOCKET_NAME)
        except:
            pass
        os.umask(0)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.bind(XDB.SOCKET_NAME)
        os.fchmod(self.sock.fileno(), 0777)
        os.chmod(XDB.SOCKET_NAME, 0777)

        # start the EXOS expy background process
        if self.stack_mode == '1':
            slot_clause = 'slot {0}'.format(os.getenv('EXOS_STACK_SLOT', '1'))
        else:
            slot_clause = ''
        cmd = 'start process {0} {1}'.format(XDB.PROCESS_NAME, slot_clause)

        # delay starting the back end until we get the socket listenter up
        cmd_thread = threading.Thread(target=self.delayed_exos_cmd, args=(2, cmd))
        cmd_thread.start()

        #exos_clicmd('start process {0} {1}'.format(XDB.PROCESS_NAME, slot_clause))

        # listen for the backend connection, if we timeout something went wrong
        try:
            self.sock.listen(1)
        except socket.timeout as msg:
            print '{0} failed to start properly'.format(XDB.PROCESS_NAME)
            return

        conn, addr = self.sock.accept()

        # read from backend and echo any received characters to the user
        while True:

            try:
                buf = conn.recv(20)
            except (TypeError, socket.timeout) as msg:
                print 'Lost connection with {0} service'.format(XDB.PROCESS_NAME)
                break

            # a buf len=0 means we are done
            if len(buf) == 0:
                break

            sys.stdout.write(buf)
            sys.stdout.flush()

        self.sock.close()
        try:
            os.remove(XDB.SOCKET_NAME)
        except:
            pass


# **********************************************************************
# Determine the run time context and invoke the proper class
# **********************************************************************
if __name__ == '__main__':
# First it will be executed as a script which will be executed in "if" part and then
# it will create a process "cablediag" which will be executed in "else" part

    if i_am_script is True:
        # Executed as script by,
        # "run diagnostics cable ports [ <port-list> | all ] "
        # or "run script cablediag.py [-p <portList>] [-f] [-d]"
        sys.tracebacklimit = 0
        try:
            diag = RunScriptCableDiag()
            diag.main()
        except (KeyboardInterrupt, SystemExit):
            pass
    else:
        # Executed as process by,
        # "create process {cablediag} python-module {cablediag} start on-demand --{arguments}"
        diag = ExpyProcessCableDiag()
        diag.main()
        sys.stdout.flush()
        exec_cli(['delete process {0}'.format(XDB.PROCESS_NAME)], ignore_errors=True)
