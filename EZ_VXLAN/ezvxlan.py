# ******************************************************
#
#  Copyright (c) Extreme Networks Inc. 2016
#  All rights reserved
#
# ******************************************************
'''
This application provides an automatic mapping of certain VLANs into VLXAN VNI's.

Two VLAN name formats will cause the app to create a VXLAN VNI automatically.
    SYS_VLAN_xxxx       - dynamic VLAN created by EXOS such as vm-tracking
    VNI_yyyyy_<something> - Manually created VLAN by user

################################################################################
SYS_VLAN_xxxx VLAN name format:
################################################################################
Features such as vm-tracking with dynamic detection enabled will received a MAC address
from a port, authenticate the MAC address and then create a MAC based VLAN with the name
SYS_VLAN_xxxx where xxxx is the VLAN tag.

This application detects VLANs created with that name and creates a VXLAN VNI with the same
xxxx number. E.g. VLAN SYS_VLAN_1010 will map to VXLAN VNI 1010. The application creates a
VXLAN VNI name of SYS_VN_xxxx.

################################################################################
VNI[-_]<vni><something> VLAN name format:
################################################################################
The second type of VLAN name can be created manually in the form VNI-yyyyy_<something>
where:
    <vni> = any number from 1-<upper VNI value>
    <something> = any string to identify the VLAN

E.g.
    create vlan VNI-10012_vm9037  tag 100
    create vlan VNI_10012remoteOffice  tag 100
    The application will look for VNI-10012_ and then create a VXLAN VNI with 10012. The
    VLAN tag is 100 and is indepentent of the name.
    VXLAN VNI name of SYS_VN_10012.

The VLXAN VNI will actually be created when the first port is added to the VLAN and will be
deleted after the last port is removed from the VLAN. By adding/removing the VXLAN VNI,
network traffic/flooding will not be sent to a switch that has no ports associated with the
attached VLAN.

On startup, the VLXAN VTEP is created using the OSPF router id for the IP address.
'''
__version__ = '2.1.0.3'
# --------------------------------------------------------------------------------
# 2.1.0.2
# xos0072410 - Starting ezvxlan script multiple times will cause core & crash
#               check for already running was removed during start. Put it back.
# --------------------------------------------------------------------------------
# 2.1.0.2
# xos0070617 - add additional special VLAN for BGP auto-peering
# --------------------------------------------------------------------------------
# 2.1.0.1
# dhammers: add NSI callback support where NSI determines the VNI
# --------------------------------------------------------------------------------
# 2.0.0.3
# dhammers: start --allvlans option. Add option to auto create VxLAN for all VLANs
#           where vlan name is not default. VNI = VID
# --------------------------------------------------------------------------------
# 2.0.0.2
# dhammers: When Extreme Fabric is enabled, any vlan is attached to a VXLAN
# --------------------------------------------------------------------------------
# 2.0.0.1
# dhammers: Add bgp support.
#           Restructured global code to be in its own class and functions.
# --------------------------------------------------------------------------------
# 1.0.0.6
# dhammers: handle processing when EXOS is doing a save
# --------------------------------------------------------------------------------

import sys
import logging
import argparse
from re import compile as re_compile


i_am_script = False
try:
    import exsh
    import json
    i_am_script = True
except:
    import Queue
    from exos.api import exos_dbapi as dbapi
    import threading
    import cProfile
    import pstats


################################################################################
# CONSTANTS

PROCESS_NAME = 'ezvxlan'
# EXOS dynamic VLAN prefix
SYS_VLAN_PREFIX = 'SYS_VLAN_'

# EXOS manually created VLAN that VXLAN looks for
VNI_VLAN_PATTERN = 'VNI[-_](\d+)\s*'
VNI_VLAN_RE = re_compile(VNI_VLAN_PATTERN)

# VXLAN generated name for VNI's created by this app
VN_PREFIX = 'SYS_VN_'
VN_FORMAT = VN_PREFIX + '{0:04d}'

VR_DEFAULT = 'VR-Default'

# Extreme Fabric VLAN prefix
EF_PREFIX = ['FBRC_VLAN_', 'SYS_BGP_']


class Xos(object):

    # CONSTANTS for dbapi()
    class Db(object):
        LOGIN = 'admin'
    DB = Db()

    class Vlan(object):
        MODULE = 'vlan'

        class Vlan(object):
            BLOCK = 'vlan'
            NAME = 'name'
            VLAN_TAG = 'tag'
        VLAN = Vlan()

        class VlanMap(object):
            BLOCK = 'vlanMap'
            NAME = 'vlanName'
            LIST = 'vlanList'
        VMAP = VlanMap()

        class Port(object):
            BLOCK = 'vlanPort'
            NAME = 'vlanName'
            TAG_PORTS = 'taggedPorts'
            UNTAG_PORTS = 'untaggedPorts'
        PORT = Port()

    VLAN = Vlan()

    class TunnelMgr(object):
        MODULE = 'otm'

        class VirtualNetwork(object):
            BLOCK = 'virtualNetwork'

            NAME = 'name'
            VNI = 'id'
            VLAN_NAME = 'vlan'
            ACTION = 'action'
            CREATE_ACTION = 'create'
            ADD_ACTION = 'configure'
            DELETE_ACTION = 'delete'

            ENCAP = 'encap'
            ENCAP_NONE = '0'
            ENCAP_VXLAN = '1'
            ENCAP_NVGRE = '2'

            MONITOR = 'monitorEnabled'
            MONITOR_ENABLED = '1'
            MONITOR_DISABLED = '0'

            FLOOD_MODE = 'floodMode'
            FLOOD_MODE_DEFAULT = '1'

        VN = VirtualNetwork()

    OTM = TunnelMgr()

    class VirtualSwitchManager(object):
        MODULE = 'vsm'

        class MlagPeer(object):
            BLOCK = 'mLagPeer'

            PEER_NAME = 'peerName'
            PEER_IP = 'peerIpAddr'
            LOCAL_IP = 'localIpAddr'
        MPEER = MlagPeer()

    VSM = VirtualSwitchManager()

    class MultiCastManager(object):
        MODULE = 'mcmgr'

        class IgmpSnooping(object):
            BLOCK = 'igmpSnoop'

            ENABLE = 'enable'
            ENABLED = '1'
            DISABLED = '0'

            VLAN_NAME = 'vlan'
        IS = IgmpSnooping()
    MCM = MultiCastManager()

    # CONSTANTS for EXOS vlan callbacks
    class VlanPortCallback(object):
        NAME = 'vlan_name'
        ID = 'vlan_id'
        PORT = 'port'
    VPC = VlanPortCallback()


XDB = Xos()


# ################################################################################
# EXPY common functions
class EzVxlanExpyBase(object):

    def __init__(self):
        # root logger
        # Create the vxlan logging mechanism
        # self.rlog = logging.getLogger('')

        self.log = logging.getLogger('.{0}'.format(PROCESS_NAME))

        self.log.setLevel(logging.INFO)
        if not len(self.log.handlers):
            self.log_handler = logging.StreamHandler(sys.stderr)
            self.log_handler.setFormatter(logging.Formatter(
                '%(levelname)s:%(threadName)s:%(name)s:%(funcName)s:%(lineno)s:: '
                '%(message)s'))
            self.log.addHandler(self.log_handler)
            # self.rlog.addHandler(self.log_handler)

    def exos_cmd(self, cmd=[]):
        from exos.api import exec_cli
        from time import sleep
        for line in cmd:
            self.log.debug(line)

        for retry in xrange(10):
            try:
                reply = exec_cli(cmd, ignore_errors=False)
                self.log.debug(reply)
                return reply
            except Exception as msg:
                self.log.debug('EXOS CLI ERROR: {0}'.format(str(msg)))
                sleep(1)

        self.log.debug('EXOS CLI ERROR. Command not processed: {0}'.format(str(msg)))
        return None

    def db_dbapi(self, login=None,
                 mod=None,
                 obj=None,
                 index_fields=[],
                 data_fields=[],
                 param_fields={},
                 op=None,
                 op_flags=None):
        params = {
            "login": login,
            'mod': mod,
            'obj': obj,
            'index_fields': index_fields,
            'data_fields': data_fields,
            'param_fields': param_fields,
            'op': op,
            'op_flags': op_flags
            }
        self.log.debug(params)

        if login is None:
            login = 'admin'

        if mod is None:
            self.log.warning('Module name is missing')
            return None

        if obj is None:
            self.log.warning('Object name is missing')
            return None

        cursor = self.cm_conn.cursor()
        if op is None:
            req = dbapi.request()
        else:
            req = dbapi.request(op=op)

        if op_flags is not None:
            # earlier releases do not support this option
            try:
                req._op_flag |= op_flags
            except:
                pass

        if index_fields:
            for idxf in index_fields:
                req.add_index(dbapi.Column((mod, obj), idxf))

        if data_fields:
            for dataf in data_fields:
                req.add_field(dataf, dbapi.Column((mod, obj), dataf))

        if param_fields:
            for param_key, param_value in param_fields.items():
                req.add_param(dbapi.Column((mod, obj), param_key), param_value)

        while True:
            try:
                self.log.debug('Calling cursor.execute(req) {0}:{1}'.format(mod, obj))
                cursor.execute(req)
                break
            except dbapi.ModuleUnavailable as m:
                self.log.debug('dpapi call not ready for {0}:{1}'.format(mod, obj))
                m.when_ready()
                continue
            except Exception as m:
                self.log.debug('dpapi call Exception {0}:{1} {2}'.format(mod, obj, m))
                if 'save' in str(m):
                    self.log.debug('Retrying')
                    continue
                return None

        return cursor


################################################################################
# EXOS expy VXLAN global settings
class EzVxlanExpyGlobal(EzVxlanExpyBase):
    def __init__(self):
        super(EzVxlanExpyGlobal, self).__init__()
        self.ospf_extensions_enabled = False
        self.ospfAdminState = None
        self.first_time = True
        self.fabric_option = None # command line fabric support requested
        self.fabric_enabled = None # current status of fabric feature
        self.fabric_router_id = None # BGP router id, for LTEP
        self.allvlans = None # auto create VxLAN for all vlans except default (vid=1)

    def global_set_vxlan(self):
        # main global entry point
        self.log.debug('Called')

        # add all ports to vxlan
        self.global_set_vxlan_ports()
        # determine if Extreme Fabric is enabled
        self.global_get_frabric()

        # check if bgp has a router ID
        router_id, vr = self.global_bgp_has_router_id()
        if router_id:
            # perform any adjustments to bgp to support vxlan
            self.global_set_bgp_values()
            self.global_set_ltep(router_id, vr)
            return

        # check if ospf has a router id
        router_id, vr = self.global_ospf_has_router_id()
        if router_id:
            # perform any adjustments to ospf to support vxlan
            self.global_set_ospf_values()
            self.global_set_ltep(router_id, vr)
            return

    def global_set_vxlan_ports(self):
        # config virtual-network add network ports all

        # Only do this once
        if self.first_time is False:
            return
        self.first_time = False

        self.log.debug('Called')

        MODULE = 'otm'
        BLOCK = 'virtualNetTerm'
        ENCAP = 'encap'
        PORTS = 'ports'
        PORTS_ALL = '*'
        ACTION = 'action'
        ACTION_CONFIGURE = 'configure'

        self.db_dbapi(mod=MODULE,
                      obj=BLOCK,
                      param_fields={
                          ENCAP: 1,
                          PORTS: PORTS_ALL,
                          ACTION: ACTION_CONFIGURE},
                      op=dbapi.CM_OP_SET)

    def global_bgp_has_router_id(self):
        self.log.debug('Called')

        MOD = "bgp"
        OBJ = "bgpCfgGlobalReadWrite"
        ADMIN_STATE = "bgpCfgAdminStatus"
        ROUTER_ID = "bgpCfgLocalIdentifier"
        VR = "bgpCfgVrId"

        bgp_cursor = self.db_dbapi(mod=MOD,
                                   obj=OBJ,
                                   index_fields=[VR],
                                   data_fields=[ADMIN_STATE, ROUTER_ID, VR],
                                   param_fields={VR: VR_DEFAULT}
                                   )

        bgp_admin_state = None
        bgp_router_id = None
        bgp_vr = None
        if bgp_cursor:
            # expecting only a single row
            for reply in bgp_cursor.iterrow():
                self.log.debug(reply)
                bgp_admin_state = reply.field_values[ADMIN_STATE]
                bgp_router_id = reply.field_values[ROUTER_ID]
                bgp_vr = reply.field_values[VR]
                break
        else:
            return (None, None)

        if bgp_admin_state == '1':
            if bgp_router_id != '0.0.0.0':
                self.log.debug('{}, {}'.format(bgp_router_id, bgp_vr))
                return (bgp_router_id, bgp_vr)
        return (None, None)

    def global_set_bgp_values(self):
        self.log.debug('Called')

        # nothing to do for BGP vxlan
        return

    def global_ospf_has_router_id(self):
        self.log.debug('Called')

        # does OSPF have a router_id
        MODULE = 'ospf'
        BLOCK = 'ospfGlobal'
        ADMIN_STATE = 'ospfAdminStat'
        ROUTER_ID = 'ospfRouterId'
        EXTENSIONS = 'ospfVxLanExtensions'

        # get OSPF global config to get router id and extensions setting
        ospf_cursor = self.db_dbapi(mod=MODULE,
                                    obj=BLOCK,
                                    data_fields=[ADMIN_STATE,
                                                 ROUTER_ID,
                                                 EXTENSIONS])

        self.ospfAdminState = None
        ospfRouterId = None
        self.ospfVxLanExtensions = None
        if ospf_cursor:
            # expecting only a single row
            for reply in ospf_cursor.iterrow():
                self.log.debug(reply)
                self.ospfAdminState = reply.field_values[ADMIN_STATE]
                ospfRouterId = reply.field_values[ROUTER_ID]
                self.ospfVxLanExtensions = reply.field_values[EXTENSIONS]
                break
        else:
            return (None, None)

        if self.ospfAdminState == '1':
            if ospfRouterId != '0.0.0.0':
                self.log.debug('{}, {}'.format(ospfRouterId, VR_DEFAULT))
                return (ospfRouterId, VR_DEFAULT)
        return (None, None)

    def global_set_ospf_values(self):
        self.log.debug('Called')

        # check if OSPF vxlan extensions has been enabled
        if self.ospf_extensions_enabled is True:
            # we do this once at startup so we don't keep messing with OSPF
            return

        self.ospf_extensions_enabled = True

        if self.ospfVxLanExtensions == '0':
            cmd = []
            if self.ospfAdminState == '1':  # OSPF is enabled. must be disabled to add extensions
                cmd.append('disable ospf')
            cmd.append('enable ospf vxlan-extensions')
            if self.ospfAdminState == '1':  # OSPF was enabled. turn it back on
                cmd.append('enable ospf')
            self.exos_cmd(cmd)

    def global_set_ltep(self, router_id, vr):
        self.log.debug('Called, router_id={}, vr={}'.format(router_id, vr))
        BLOCK = 'localTep'
        VR = 'vrName'
        IP = 'ipAddress'
        INSTANCE = 'instance'
        IS_MLAG = 'isMLag'

        # Check if the local LTEP has been configured with an IP address
        ltep_cursor = self.db_dbapi(mod=XDB.OTM.MODULE,
                                    obj=BLOCK,
                                    index_fields=[VR, IP, INSTANCE],
                                    data_fields=[IP, VR, IS_MLAG])

        ltep_ip = None
        ltep_vr = None
        ltep_is_mlag = None
        if ltep_cursor:
            # expecting only a single row
            for reply in ltep_cursor.iterrow():
                self.log.debug(reply)
                ltep_ip = reply.field_values[IP]
                ltep_vr = reply.field_values[VR]
                ltep_is_mlag = reply.field_values[IS_MLAG]
                break
        else:
            return

        self.log.debug('ltep_ip={}, ltep_vr={}, ltep_is_mlag={}'.format(
            ltep_ip,
            ltep_vr,
            ltep_is_mlag))

        # VXLAN LTEP config (Local Termination End Point)
        if ltep_ip and len(ltep_ip) and ltep_ip == router_id and ltep_vr == vr:
            # ltep IP address already configured
            self.log.debug('LTEP already configured')
            return

        # see if we are part of an MLAG
        mlag_cursor = self.db_dbapi(mod=XDB.VSM.MODULE,
                                    obj=XDB.VSM.MPEER.BLOCK,
                                    index_fields=[XDB.VSM.MPEER.PEER_NAME],
                                    data_fields=[XDB.VSM.MPEER.PEER_NAME])

        mlag_peer_name = None
        if mlag_cursor:
            # expecting only a single row
            for reply in mlag_cursor.iterrow():
                self.log.debug(reply)
                mlag_peer_name = reply.field_values[XDB.VSM.MPEER.PEER_NAME]
                break
        else:
            return

        if mlag_peer_name is not None:
            # switch is part of an MLAG, LTEP cannot be automatically configured
            # user needs to create a vlan on each MLAG peer with a IP address for the LTEP
            return

        # LTEP IP address has not been configured
        cmd = []
        cmd.append(
            'configure virtual-network local-endpoint ipaddress {ip} vr {vr}'.format(
                ip=router_id,
                vr=vr))
        self.exos_cmd(cmd)

    def global_get_frabric(self):
        # see if Extreme Fabric is enabled
        self.log.debug('Called')

        # only examine Extreme Fabric settings if requested by a command line option
        if self.fabric_option is False:
            return

        MODULE = 'bgp'
        BLOCK = 'easyFabricCfg'
        EF_ROUTER_ID = 'efLocalRouterId'
        EF_STATE = 'enabledState'

        # Check if the local LTEP has been configured with an IP address
        ef_cursor = self.db_dbapi(mod=MODULE,
                                    obj=BLOCK,
                                    data_fields=[EF_ROUTER_ID, EF_STATE])
        if ef_cursor:
            # expecting only a single row
            for reply in ef_cursor.iterrow():
                self.log.debug(reply)
                self.fabric_router_id = reply.field_values[EF_ROUTER_ID]
                ef_enabled = True if reply.field_values[EF_STATE] == '1' else False
                if ef_enabled != self.fabric_enabled and ef_enabled is True:
                    self.fabric_enabled = ef_enabled
                    self.create_existing_vlans_at_startup()
                break
        else:
            self.fabric_enabled = None
            self.fabric_router_id = None
            return

    def create_existing_vlans_at_startup(self):
        'when our process starts, scan the VLANs for ones that match our special cases'
        from exos.api import (ready, vlan)
        from _exos_ext_cmfe import CM_FLAG_GETNEXT
        self.log.debug('Called')
        ready()

        vlan.notify.vlan_port_create.add_observer(self.cmcb_vlan_port_create)
        vlan.notify.vlan_port_delete.add_observer(self.cmcb_vlan_port_delete)
        # vlan.notify.vlan_create.add_observer(self.cmcb_vlan_create)
        vlan.notify.vlan_delete.add_observer(self.cmcb_vlan_delete)

        # support in EXOS 22.4 and later
        try:
            vlan.notify.vlan_update_nsi.add_observer(self.cmcb_vlan_nsi_update)
            vlan.notify.vlan_delete_nsi.add_observer(self.cmcb_vlan_nsi_delete)
        except:
            pass
        # queue up initial vlan config

        self.bulk_init = True
        self.global_set_vxlan()
        cursor = self.db_dbapi(mod=XDB.VLAN.MODULE,
                               obj=XDB.VLAN.VMAP.BLOCK,
                               index_fields=[XDB.VLAN.VMAP.LIST],
                               data_fields=[XDB.VLAN.VMAP.NAME],
                               op_flags=CM_FLAG_GETNEXT)  # this object only supports next

        if cursor is None:
            return

        # build a vlan name list of only the names that match our special pattern
        vname_list = []
        for vmap in cursor.iterrow():
            vlan_name = vmap.field_values[XDB.VLAN.VMAP.NAME]
            # check if VNI is assigned to VLAN
            vni, vid = self.vlan_name_to_nsi(vlan_name)
            if vni:
                vname_list.append(vlan_name)
            elif self.is_vxlan_vlan(vlan_name):
                vname_list.append(vlan_name)

        self.log.debug(vname_list)
        for vlan_name in vname_list:
            # Check if VLAN has ports. If not, don't create the VNI yet
            if self.does_vlan_have_ports(vlan_name) is True:
                self.q.put((self.do_exos_add, vlan_name))
        self.dump_trace = True
        self.bulk_init = False




################################################################################
# EXOS interface
class EzVxlanExpy(EzVxlanExpyGlobal):
    'These functions run in the expy context'
    # create a queue to be shared by CM context and ezvxlan

    def __init__(self):
        super(EzVxlanExpy, self).__init__()
        self.controller_port = None
        self.q = Queue.Queue(maxsize=4*1024)
        self.bulk_init = False
        self.cm_conn = None
        self.dump_trace = False
        self.pr = None
        self.dispatch_timeout = 60  # periodically check global settings

    # Connect to EXOS EPM
    def __call__(self):
        'expy process main'
        self.log.debug('Called')

        # init the profiler
        self.pr = cProfile.Profile(builtins=False)
        self.get_params()

        # start a backend dispatcher_thread for callbacks
        self.log.debug('start dispatcher')
        dispatcher_thread = threading.Thread(target=self.dispatcher,
                                             name='{0}-dispatcher'.format(PROCESS_NAME))
        dispatcher_thread.start()

        # connect to CM DB
        self.cm_conn = dbapi.connect(XDB.DB.LOGIN)

        self.log.debug('start initCM')
        self.initCM()

        self.log.debug('wait forever')
        dispatcher_thread.join()

        self.log.debug('Process exit. This should not happen.')

    def initCM(self):
        self.log.debug('Called')
        from exos.api.cmbackend import (cmbackend_init, CmAgent)

        # The context for this class is the main expy thread
        # Callbacks invoke these class funcions
        # We pass in the our EzVxlanExpy instance so it can reference
        # those functions/veriables directly
        class VxlanCmAgent(CmAgent):

            def __init__(self, vxexpy):
                super(VxlanCmAgent, self).__init__()
                self.vxexpy = vxexpy

            def event_load_start(self):
                self.vxexpy.log.debug('Called event_load_start')

            def event_load_complete(self):
                self.vxexpy.log.debug('Called event_load_complete')

            def event_save_start(self):
                self.vxexpy.log.debug('Called event_save_start')

            def event_save_complete(self):
                self.vxexpy.log.debug('Called event_save_complete')

            def event_generate_default(self):
                self.vxexpy.log.debug('Called event_generate_default')
                self.vxexpy.q.put((self.vxexpy.create_existing_vlans_at_startup,))
        cmbackend_init(VxlanCmAgent(self), )

    # parse command line options
    def get_params(self):
        'parse any command line args'
        self.log.debug('Called')
        parser = argparse.ArgumentParser(prog=PROCESS_NAME)

        parser.add_argument(
            '-d', '--debug',
            help='Enable debug',
            action='store_true',
            dest='debug',
            default=False)

        parser.add_argument(
            '-p', '--port',
            help='Silent Controller port. Add this port to any newly created VLAN',
            default=None)

        options = parser.add_mutually_exclusive_group()
        options.add_argument(
            '--fabric',
            help='Extreme Fabric mode. When Fabric is enabled, auto create VxLAN VNIs for all VLANs',
            action='store_true',
            default=False)

        options.add_argument(
            '--allvlans',
            help='Automatically create VxLAN VNIs for all VLANs except default. VNI = VID',
            action='store_true',
            default=None)

        args = parser.parse_args()
        if args.debug is True:
            # self.rlog.setLevel(logging.DEBUG)
            self.log.setLevel(logging.DEBUG)
        self.log.debug(args)

        # save controller port
        self.controller_port = args.port
        self.fabric_option = args.fabric
        self.allvlans = args.allvlans

    def does_vlan_have_ports(self, vlan_name):
        'test if a vlan has any tagged/untagged ports and return True if it does'
        self.log.debug('Called with {0}'.format(vlan_name))
        cursor = self.db_dbapi(mod=XDB.VLAN.MODULE,
                               obj=XDB.VLAN.PORT.BLOCK,
                               data_fields=[XDB.VLAN.PORT.TAG_PORTS,
                                            XDB.VLAN.PORT.UNTAG_PORTS],
                               param_fields={XDB.VLAN.PORT.NAME: vlan_name})

        if cursor is None:
            return False

        # expecting only a single row
        for row in cursor.iterrow():
            self.log.debug(row)
            if len(row.field_values[XDB.VLAN.PORT.TAG_PORTS]) or\
               len(row.field_values[XDB.VLAN.PORT.UNTAG_PORTS]):
                self.log.debug('VLAN {0} has ports'.format(vlan_name))
                return True
        self.log.debug('VLAN {0} does not have ports'.format(vlan_name))
        return False

    def does_vni_exist(self, vni):
        'test if a VNI exists'
        cursor = self.db_dbapi(mod=XDB.OTM.MODULE,
                               obj=XDB.OTM.VN.BLOCK,
                               data_fields=[XDB.OTM.VN.NAME, XDB.OTM.VN.VNI],
                               param_fields={XDB.OTM.VN.NAME: self.vni_to_name(vni)})

        if cursor is None:
            return False

        # search until VNI matches
        for row in cursor.iterrow():
            self.log.debug(row)
            # convert the DB value to an int()
            try:
                otm_vni = int(row.field_values[XDB.OTM.VN.VNI])
            except TypeError:
                self.log.error('Error converting otm_vni for VLAN: {0}'.format(
                    row.field_values[XDB.OTM.VN.VNI]))
                continue

            # did we find the matching VNI?
            if otm_vni == vni:
                self.log.debug('VNI {0} does exists'.format(vni))
                return True

        self.log.debug('VNI {0} does not exist'.format(vni))
        return False

    ################################################################################
    # VLAN/VXLAN name funcitons
    @staticmethod
    def vni_to_name(vni):
        'format a VNI name'
        return VN_FORMAT.format(vni)

    @staticmethod
    def parse_sys_vlan_name(vlan_name):
        'parse the vni,vid out of SYS_VLAN_0000, where 0000 is the trailing number vlan tag'
        vname_parts = vlan_name.split('_')
        try:
            vni = int(vname_parts[-1])
            vid = vni
        except (TypeError, ValueError):
            return None, None

        return vni, vid

    def parse_vni_vlan_name(self, vlan_name, vni_only=False):
        'parse the vni,vid out of VNI-00000_<name>, where 00000 follows VNI-'
        self.log.debug('Called {0} vni_only={1}'.format(vlan_name, vni_only))

        # parse the VLAN name to extract the VNI
        result = VNI_VLAN_RE.match(vlan_name)
        if result is None:
            return None, None

        vni_number = result.group(1)
        self.log.debug('Vlan name={vname}, VNI={vni}'.format(vname=vlan_name,
                                                             vni=vni_number))

        # token should be VNI
        try:
            vni = int(vni_number)
        except ValueError:
            self.log.debug('Bad VNI vlan name format {vni}'.format(vni=vni))
            vni = None

        if vni_only is True:
            return vni, None

        vid = self.vlan_name_to_vid(vlan_name)
        # if the VLAN name doesn't have a valid VNI-00000_<name> format, then just
        # use the tag as the vni
        if vni is None:
            vni = vid

        return vni, vid

    def vlan_name_to_vid(self, vlan_name):
        # lookup the VLAN name to get the tag
        cursor = self.db_dbapi(mod=XDB.VLAN.MODULE,
                               obj=XDB.VLAN.VLAN.BLOCK,
                               data_fields=[XDB.VLAN.VLAN.VLAN_TAG],
                               param_fields={XDB.VLAN.VLAN.NAME: vlan_name})

        if cursor is None:
            self.log.debug('Database did not return a cursor')
            return None

        # expecting only a single row
        for reply in cursor.iterrow():
            self.log.debug(reply)
            try:
                return int(reply.field_values[XDB.VLAN.VLAN.VLAN_TAG])
            except:
                break

        self.log.debug('get vlan.vlan failed')
        return None

    def vlan_name_to_nsi(self, vlan_name):
        # returns vni, vid if present
        cursor = self.db_dbapi(mod='lldp',
                               obj='faMapping',
                               index_fields=['vlan_name', 'nsi'],
                               data_fields=['vlan_name', 'nsi', 'vlanId']
                               )

        if cursor is None:
            self.log.debug('Database did not return a cursor')
            return None, None

        # for this structure we have to loop through looking for a matching vlan name
        for reply in cursor.iterrow():
            if vlan_name == reply.field_values['vlan_name']:
                self.log.debug(reply)
                try:
                    return (int(reply.field_values['nsi']), int(reply.field_values['vlanId']))
                except:
                    break

        self.log.debug('get nsi failed')
        return None, None

    def get_vni_vid(self, vlan_name, vni_only=False):
        #given a vlan name, determine the VNI and VLAN ID
        vni = None
        vid = None
        self.log.debug(vlan_name)

        if vlan_name.startswith(SYS_VLAN_PREFIX):
            vni, vid = self.parse_sys_vlan_name(vlan_name)
        elif VNI_VLAN_RE.match(vlan_name) is not None:
            vni, vid = self.parse_vni_vlan_name(vlan_name, vni_only)
        elif self.fabric_enabled is True:
            vid = self.vlan_name_to_vid(vlan_name)
            vni = vid
        elif self.allvlans is True:
            vid = self.vlan_name_to_vid(vlan_name)
            vni = vid
        else:
            # query the vlan to see if it has an nsi attribute
            vni, vid = self.vlan_name_to_nsi(vlan_name)

        self.log.debug('vni {0}, vid {1}'.format(vni, vid))
        return vni, vid

################################################################################
# Callback and CLI action functions
    def dispatcher(self):
        'this thread dispatcher function dispatches calls to other backend processes'
        self.log.debug('Called')

        self.start_profiler()

        while True:
            # adding the initial scan for vlans at startup is measured
            if self.q.empty() is True and self.dump_trace is True:
                self.stop_profiler()
                self.dump_trace = False
                self.start_profiler()

            # queue entries are function followed by optional args
            try:
                dspatch = self.q.get(timeout=self.dispatch_timeout)
            except Queue.Empty:
                self.global_set_vxlan()
                continue
            it = iter(dspatch)
            func = it.next()
            params = list(it)
            self.log.debug('dispatching {0}({1})'.format(func, params))
            func(*params)

        self.log.debug('Exit')

    def do_exos_add(self, vlan_name, vni=None, vid=None):
        'Running in its own thread, create a VNI and add the VLAN to it'
        # some callbacks provide both VNI and VID
        self.log.debug('Called with {} vni={}'.format(vlan_name, vni))

        # caller did not provide a VNI
        if vni is None:
            # check if this vlan has a NSI/VNI assigned to it
            vni, vid = self.vlan_name_to_nsi(vlan_name)
            if vni is None:
                # is this a VLAN with a special name
                if self.is_vxlan_vlan(vlan_name):
                    # extract the VNI, VID from the name
                    vni, vid = self.get_vni_vid(vlan_name, vni_only=False)
                else:
                    return
        if vni is None or vid is None:
            return
        if self.does_vlan_have_ports(vlan_name) is False:
            return

        vn_name = self.vni_to_name(vni)

        # 'disable igmp snooping {vname}'.format(vname=vlan_name)
        self.db_dbapi(mod=XDB.MCM.MODULE,
                      obj=XDB.MCM.IS.BLOCK,
                      param_fields={
                          XDB.MCM.IS.ENABLE: XDB.MCM.IS.DISABLED,
                          XDB.MCM.IS.VLAN_NAME: vlan_name},
                      op=dbapi.CM_OP_SET)

        if self.does_vni_exist(vni) is False:
            # cmd.append('create virtual-network {vn}'.format(vn=vn_name))
            self.db_dbapi(mod=XDB.OTM.MODULE,
                          obj=XDB.OTM.VN.BLOCK,
                          param_fields={
                              XDB.OTM.VN.ACTION: XDB.OTM.VN.CREATE_ACTION,
                              XDB.OTM.VN.NAME: vn_name,
                              XDB.OTM.VN.FLOOD_MODE: XDB.OTM.VN.FLOOD_MODE_DEFAULT},
                          op=dbapi.CM_OP_SET)

        self.db_dbapi(mod=XDB.OTM.MODULE,
                      obj=XDB.OTM.VN.BLOCK,
                      param_fields={
                          XDB.OTM.VN.NAME: vn_name,
                          XDB.OTM.VN.ACTION: XDB.OTM.VN.ADD_ACTION,
                          XDB.OTM.VN.VLAN_NAME: vlan_name,
                          XDB.OTM.VN.ENCAP: XDB.OTM.VN.ENCAP_VXLAN,
                          XDB.OTM.VN.VNI: vni,
                          XDB.OTM.VN.MONITOR: XDB.OTM.VN.MONITOR_ENABLED
                          },
                      op=dbapi.CM_OP_SET)
        return
        # cmd.append('configure virtual-network {vn} add {vname}'.format(
        #     vn=vn_name, vname=vlan_name))
        self.db_dbapi(mod=XDB.OTM.MODULE,
                      obj=XDB.OTM.VN.BLOCK,
                      param_fields={
                          XDB.OTM.VN.NAME: vn_name,
                          XDB.OTM.VN.ACTION: XDB.OTM.VN.ADD_ACTION,
                          XDB.OTM.VN.VLAN_NAME: vlan_name},
                      op=dbapi.CM_OP_SET)

        # cmd.append('configure virtual-network {vn} vxlan vni {vni}'.format(vn=vn_name, vni=vni))
        self.db_dbapi(mod=XDB.OTM.MODULE,
                      obj=XDB.OTM.VN.BLOCK,
                      param_fields={
                          XDB.OTM.VN.NAME: vn_name,
                          XDB.OTM.VN.ACTION: XDB.OTM.VN.ADD_ACTION,
                          XDB.OTM.VN.ENCAP: XDB.OTM.VN.ENCAP_VXLAN,
                          XDB.OTM.VN.VNI: vni},
                      op=dbapi.CM_OP_SET)

        # cmd.append('configure virtual-network {vn} monitor on'.format(vn=vn_name))
        self.db_dbapi(mod=XDB.OTM.MODULE,
                      obj=XDB.OTM.VN.BLOCK,
                      param_fields={
                          XDB.OTM.VN.NAME: vn_name,
                          XDB.OTM.VN.ACTION: XDB.OTM.VN.ADD_ACTION,
                          XDB.OTM.VN.MONITOR: XDB.OTM.VN.MONITOR_ENABLED},
                      op=dbapi.CM_OP_SET)

    def do_exos_delete(self, vlan_name, is_vlan=False, vni=None, vid=None):
        'running it its own thread, Delete a VNI if there are no more ports on its vlan'
        # when deleting an entire VLAN, we only need the VNI
        # some callbacks provide the VNI and some to not
        if vni is None:
            vni, vid = self.get_vni_vid(vlan_name, vni_only=is_vlan)
        self.log.debug('vni {0}, vid {1}'.format(vni, vid))
        if vni is None:
            return

        # if the VLAN still has ports, do not remove the VXLAN VNI
        if vid is not None and self.does_vlan_have_ports(vlan_name) is True:
            return

        # cmd = []
        # cmd.append('delete virtual-network {vni}'.format(vni=self.vni_to_name(vni)))
        # self.exos_cmd(cmd)
        self.db_dbapi(mod=XDB.OTM.MODULE,
                      obj=XDB.OTM.VN.BLOCK,
                      param_fields={
                          XDB.OTM.VN.NAME: self.vni_to_name(vni),
                          XDB.OTM.VN.ACTION: XDB.OTM.VN.DELETE_ACTION},
                      op=dbapi.CM_OP_SET)

    def do_exos_add_controller_port(self, vlan_name, port):
        self.log.debug('vlan_name={vname}, port={p}'.format(vname=vlan_name, p=port))
        cmd = []
        cmd.append('configure vlan {vname} add ports {p} tagged'.format(vname=vlan_name, p=port))
        self.exos_cmd(cmd)

    def is_vxlan_vlan(self, vlan_name):
        if vlan_name is None:
            self.log.debug('VLAN name {} not is special'.format(vlan_name))
            return False
        if self.fabric_enabled is True:
            for prefix in EF_PREFIX:
                if not vlan_name.startswith(prefix):
                    # if fabric is enabled, every VLAN connects to a VXLAN except for fabric VLANs
                    self.log.debug('VLAN name {} is special. --fabric enabled'.format(vlan_name))
                    return True
        if self.allvlans is True and vlan_name.lower() != 'default':
            # every VLAN connects to a VXLAN except for default (vid=1)
            self.log.debug('VLAN name {} is special. --allvlans enabled'.format(vlan_name))
            return True
        if vlan_name.startswith(SYS_VLAN_PREFIX) or VNI_VLAN_RE.match(vlan_name) is not None:
            return True
        self.log.debug('VLAN name {} not is special'.format(vlan_name))
        return False

    # These functions are CM callbacks and run on the CM thread.
    # Any work we have to do is offloaded to our own thread
    def delete_vni(self, vlan_name, is_vlan=False):
        self.q.put((self.do_exos_delete, vlan_name, is_vlan))

    def cmcb_vlan_create(self, *args, **kwargs):
        'EXOS callback when a VLAN is created'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        self.q.put((self.do_exos_add, vlan_name))

    def cmcb_vlan_port_create(self, *args, **kwargs):
        'EXOS callback when a port is added to a VLAN'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        self.q.put((self.do_exos_add, vlan_name))

    def cmcb_vlan_port_delete(self, *args, **kwargs):
        'EXOS callback when a port is deleted from a VLAN'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        self.delete_vni(vlan_name, False)

    def cmcb_vlan_delete(self, *args, **kwargs):
        'EXOS callback when a port is deleted from a VLAN'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        self.delete_vni(vlan_name, True)

    def cmcb_vlan_nsi_update(self, *args, **kwargs):
        'EXOS callback when a NSI is updated on a VLAN'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        vid = kwargs.get('vlan_id', None)
        for nsi_type, vni in kwargs.get('vlan_nsi_list', []):
            self.q.put((self.do_exos_add, vlan_name, vni, vid))

    def cmcb_vlan_nsi_delete(self, *args, **kwargs):
        'EXOS callback when a NSI is deleted from a VLAN'
        self.log.debug('args={args}\nkwargs={kwargs}'.format(args=args, kwargs=kwargs))
        vlan_name = kwargs.get(XDB.VPC.NAME, None)
        for nsi_type, vni in kwargs.get('vlan_nsi_list', []):
            self.q.put((self.do_exos_delete, vlan_name, True, vni))


    def start_profiler(self):
        # when profiling, comment out the return below
        return
        self.pr.enable()

    def stop_profiler(self):
        # when profiling, comment out the return below
        return
        import StringIO
        self.pr.disable()
        s = StringIO.StringIO()
        # ps = pstats.Stats(self.pr, stream=s).sort_stats('time')
        ps = pstats.Stats(self.pr, stream=s).sort_stats('cumulative')
        ps.print_stats()
        print(s.getvalue())


class EzVxlanScript(object):
    'convenient way to start/stop this is "run script ezvxlan.py start/stop"'

    def __init__(self):
        self.action_dict = {'start': self.start_ezvxlan,
                            'stop': self.stop_ezvxlan,
                            'restart': self.restart_ezvxlan,
                            'show': self.show_ezvxlan}
        self.log = logging.getLogger('.{0}'.format(PROCESS_NAME))
        self.log.setLevel(logging.INFO)
        if not len(self.log.handlers):
            self.log_handler = logging.StreamHandler(sys.stderr)
            self.log_handler.setFormatter(logging.Formatter(
                '%(levelname)s:%(threadName)s:%(name)s:%(funcName)s.%(lineno)s:: '
                '%(message)s'))
            self.log.addHandler(self.log_handler)

    def __call__(self):
        args = self.get_params()
        if args is None:
            return

        if args.debug:
            self.log.setLevel(logging.DEBUG)

        self.log.debug(args)

        # call function based on command line args.action
        func = self.action_dict.get(args.action)
        if func is not None:
            func(args)
        else:
            self.message_to_user("Process error. Don't know what to do with {0}".format(
                args.action))

    def get_params(self):
        # if we are running in a 'run script' environment, create the process
        parser = argparse.ArgumentParser(prog=PROCESS_NAME)
        parser.add_argument(
            '-d', '--debug',
            help='Enable debug',
            action='store_true',
            default=False)

        subparsers = parser.add_subparsers(dest='action')

        #
        # start
        start_grp = subparsers.add_parser(
            'start',
            help='Start the ezvxlan application')

        start_grp.add_argument(
            '-p', '--port',
            help='Controller port. Always add this port when VXLAN VLANs are created',
            default=None)

        start_options = start_grp.add_mutually_exclusive_group()
        start_options.add_argument(
            '--fabric',
            help='Extreme Fabric mode. When Fabric is enabled, auto create VxLAN VNIs for all VLANs',
            action='store_true',
            default=None)

        start_options.add_argument(
            '--allvlans',
            help='Automatically create VxLAN VNIs for all VLANs except default. VNI = VID',
            action='store_true',
            default=None)

        #
        # stop
        stop_grp = subparsers.add_parser(
            'stop',
            help='Stop the ezvxlan application')
        stop_grp.add_argument(
            '-k', '--keep',
            help='Keep automatically created VXLAN VNIs with names that start with {prefix}'.format(
                prefix=VN_PREFIX),
            action='store_true',
            default=False)

        #
        # restart
        restart_grp = subparsers.add_parser('restart',
                help='Restart the %(prog)s application. Useful after upgrade')
        restart_grp.set_defaults(keep=True)
        restart_grp.add_argument('-p', '--port',
                help='Controller port. Always add this port when VXLAN VLANs are created',
                default=None)

        restart_options = restart_grp.add_mutually_exclusive_group()
        restart_options.add_argument(
            '--fabric',
            help='Extreme Fabric mode. When Fabric is enabled, auto create VxLAN VNIs for all VLANs',
            action='store_true',
            default=None)

        restart_options.add_argument(
            '--allvlans',
            help='Automatically create VxLAN VNIs for all VLANs except default. VNI = VID',
            action='store_true',
            default=None)


        #
        # show
        subparsers.add_parser('show',
                              help='Show the running status of %(prog)s.')

        try:
            args = parser.parse_args()
            return args
        except SystemExit:
            return None

    def start_ezvxlan(self, args):
        # is this platform capable of VXLAN?
        try:
            exsh.clicmd('show virtual-network')
        except RuntimeError:
            self.message_to_user('This switch does not support VXLAN'.format(prefix=VN_PREFIX))
            return

        if self.is_process_running():
            self.show_ezvxlan(args)
            return

        # this dance below is a work around for an EPM crash when creating this application 'auto'
        # Don't know why it works but starting it on-demand then deleting it, then starting
        # it auto works
        self.message_to_user('Starting {pname}'.format(pname=PROCESS_NAME))
        self.exsh_clicmd('create process {pname} python-module {pname} start on-demand'.format(
            pname=PROCESS_NAME))
        self.exsh_clicmd('start process {pname}'.format(pname=PROCESS_NAME))
        self.exsh_clicmd('delete process {pname}'.format(pname=PROCESS_NAME))
        port_clause = '' if args.port is None else '-p {p}'.format(p=args.port)
        self.exsh_clicmd(
            'create process {pname} python-module {pname} start auto -- {p} {f} {v} {options}'.format(
                pname=PROCESS_NAME,
                p=port_clause,
                f='--fabric' if args.fabric else '',
                v='--allvlans' if args.allvlans else '',
                options='' if args.debug is False else '-d'))

    def stop_ezvxlan(self, args):
        if self.is_process_running():
            self.message_to_user('Stopping {pname}'.format(pname=PROCESS_NAME))
            self.exsh_clicmd('delete process {pname}'.format(pname=PROCESS_NAME))
            if args.keep is not True:
                self.message_to_user('Deleting VXLAN VNI names starting with {prefix}'.format(
                    prefix=VN_PREFIX))
                self.delete_generated_vni()
            else:
                self.message_to_user('Keeping VXLAN VNI names starting with {prefix}'.format(
                    prefix=VN_PREFIX))
        else:
            self.show_ezvxlan(args)

    def restart_ezvxlan(self, args):
        # non disruptive restart. Like after an upgrade
        self.stop_ezvxlan(args)
        self.start_ezvxlan(args)

    def show_ezvxlan(self, args):
        if self.is_process_running():
            self.message_to_user('{0}\tVersion: {1}\tprocess is running'.format(
                PROCESS_NAME, __version__))
            self.message_to_user(
                'VLANs with names SYS_VLAN_xxxx or VNI_<vni><text> are automatically mapped to SYS_VN_<vni> VTEPs')
        else:
            self.message_to_user('{0}\tVersion: {1}\tprocess is not running'.format(
                PROCESS_NAME, __version__))
            self.message_to_user(
                'VLANs with names SYS_VLAN_xxxx or VNI_<vni><text> are not mapped to SYS_VN_<vni> VTEPs automatically')

    def exsh_clicmd(self, cmd):
        try:
            self.log.debug(cmd)
            result = exsh.clicmd(cmd, capture=True)
            self.log.debug(result)
            return result
        except RuntimeError:
            self.log.debug('Command failed {0}'.format(cmd))
            return None

    def message_to_user(self, msg):
        print(msg)

    def delete_generated_vni(self):
        'called when "stop" option is provided on CLI'

        name_key = 'None'
        while True:
            cmd = 'debug cfgmgr show next maximum-rows 500 {mod}.{block} name={name_key}'.format(
                mod=XDB.OTM.MODULE,
                block=XDB.OTM.VN.BLOCK,
                name_key=name_key)
            otm_list = self.json_clicmd(cmd)
            if otm_list is None:
                return
            for otm in otm_list:
                status = otm.get('status', None)
                if str(status) in ['SUCCESS', 'ERROR']:
                    return
                name = otm.get('name', None)
                if name is None:
                    continue
                name_key = name
                if name.startswith(VN_PREFIX):
                    cmd = 'delete virtual-network {vn_name}'.format(vn_name=name)
                    self.exsh_clicmd(cmd)

    def is_process_running(self):
        # query EXOS to see if our process already exists
        data = self.json_clicmd('debug cfgmgr show one epm.epmpcb name={pname}'.format(
            pname=PROCESS_NAME))

        status = data[0].get('status')

        if status is None:
            return False

        # CM returns SUCCESS if we found the matching record
        if status == 'SUCCESS':
            self.log.debug('Process is running')
            return True

        self.log.debug('Process is not running')
        return False

    def json_clicmd(self, cmd):
        # issue debug cfgmgr CLI command to EXOS and return the JSON data
        self.log.debug(cmd)
        json_result = exsh.clicmd(cmd, capture=True)
        self.log.debug(json_result)
        # try:
        json_dict = json.loads(json_result)
        self.log.debug(json_dict)
        return json_dict.get('data')
        # except:
        #    log.debug('JSON format error')
        #    return None


if __name__ == '__main__':
    'convenient way to start this is "run script ezvxlan.py start"'
    if i_am_script is True:
        script = EzVxlanScript()
        script()
    else:
        # this is a running under expy as an EXOS process
        expy_process = EzVxlanExpy()
        expy_process()
