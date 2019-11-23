﻿.. EZ_VXLAN User Guide master file, created by
   sphinx-quickstart on Sun Apr 16 07:48:05 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: ExtremeSwitchingLogo.png
.. image:: XosLogo.png

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Easy VXLAN On-Switch Application
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ezvxlan.py is an application that runs on an EXOS ExtremeSwitch providing automatic mapping of VLANs to VxLAN VNIs.

This EXOS application is intended to be part of a larger solution involving Extreme Control and possibly other 3rd party applications. 

Version 2.1.0.3
---------------
* If BGP is running and router id is configured, uses the BGP router ID as LTEP id. If both BGP and OSPF router IDs are configured, ezvxlan.py use

    1 BGP router ID
    2 OSPF router ID

* Fabric option to work with Extreme Fabric.

    * ``start --fabric option``
    * If fabric is enabled, automatically create VXLAN VNIs for all non-fabric VLANs. 
    * VXLAN VNI is the VLAN tag (VNI=VID)

*   All VLANs option

    * ``start --allvlans option``
    * Create VXLAN VNIs for all VLANS except the Default VLAN (VID=1), regardless of VLAN name.
    * VXLAN VNI is the VLAN tag (VNI=VID)

Version 1.x
-----------
* Runs on VXLAN capable switched running EXOS 21.1.1 or later
* Monitors VLAN/port transactions from EXOS VLAN manager.
* Automatically creates VXLAN VNIs when vm-tracking creates dynamic VLANs. VNI=VLAN tag
* Automatically creates VXLAN VNIs when VLANs are created with a specific name format. VNI taken from VLAN name.
* VNI is created when first port is added to a VLAN to avoid VXLAN flooding to endpoints without assigned ports
* VNI is deleted when last port is removed from a VLAN
* VNI is deleted when entire VLAN is deleted
* Configures the Local VTEP (LTEP) with the OSPF router ID if MLAG not present, when the first VNI is created
* If MLAG is present, user must create the same VLAN with the same IP address on each MLAG peer and manually configure the LTEP IP with that VLAN IP address.
* Enables the OSPF extensions, if not already enabled, when the first VNI is created

Minimum ExtremeXOS Required
---------------------------
EXOS 21.1.1
    Requires switch hardware VXLAN support

Files
-----
.. csv-table:: Easy VXLAN Application Download
    :header: File, Description

    `summitX- ezvxlan-2.0.0.3.xmod <https://github.com/extremenetworks/EXOS_Apps/raw/master/EZ_VXLAN/summitX-ezvxlan-2.0.0.3.xmod>`_, Summit Easy VXLAN Application

Overview
--------
The application automates the creation of VXLAN Virtual Network Interfaces (VNIs) base on VLAN/port creation. By default, ezvxlan.py looks for specific VLAN name formats. If the VLAN name matches the selection criteria and at least one port is assigned to the VLAN, ezvxlan.py creates a corresponding VXLAN VNI and the VLAN is attached.

Special VLAN Names
------------------
ezvxlan.py looks for 2 special VLAN name formats to determine if an automatic mapping to a VXLAN VNI should be created.

VNI[-_]<vni><anything>

*   the name must start with VNI
*   VNI is followed by either a –(dash) or _(underscore)
*   <vni> is a number from 1 to <max VNI supported by EXOS>
*   <anything> is any sequence of characters that does not start with a number, which are allowed for a VLAN name by EXOS

* E.g.

    *   VNI-2serverGroup2000, VNI=2
    *   VNI_31247-southPolarRegion, VNI=31247
    *   VNI-101010_regional_offices, VNI=101010

SYS_VLAN_nnnn

* where nnnn is a number from 0001 to 4094.
* Names with this format can only be created by EXOS when creating dynamic VLANs for features like vm-tracking.

The purpose of supporting the VNI prefix names are to enable external applications to create these VLANs via other protocols, such as SNMP, and provide an automated method for that action to also create a corresponding VXLAN VNI and attach the VLAN.

Additional VLAN->VNI behavior ezvxlan.py 2.x
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Release ezvxlan 2.x, adds 2 new optional behaviors which are enabled using command line options to the start command

    ``run script ezvxlan.py start [ -–fabric | --allvlans ]``

    ``--fabric`` and ``--allvlans`` are mutually exclusive. I.e. either option may be used, but not both.

``–-fabric`` Interoperability with Extreme Fabric
"""""""""""""""""""""""""""""""""""""""""""""""""
This option does not depend on `Special VLAN Names`_ formats to create VXLAN VNIs.

When ezvxlan.py is started with the start ``-–fabric`` option and Extreme Fabric is enabled on the switch, all non-fabric VLANs, regardless of VLAN name, are mapped to a VXLAN. This includes the Default VLAN. For these VXLAN VNIs, the VNI = VID (VLAN tag). Fabric VLANs are not mapped to VXLAN VNIs.

Since the Default VLAN (VID=1) automatically has all ports assigned to it as untagged traffic, enabling this option could potentially produce a large untagged L2 domain.

VLAN names that follow the `Special VLAN Names`_ format will continue to create VNI = <vni> specified in the name.


``-–allvlans`` Large scale L2
"""""""""""""""""""""""""""""
This option does not depend on `Special VLAN Names`_ formats to create VXLAN VNIs.

When ezvxlan.py is started with the start ``-–allvlans`` option, with the exception of the Default VLAN (VID=1), all VLANs are mapped to VXLAN VNIs regardless of VLAN name. As VLANs are created and at least one port is assigned, a corresponding VXLAN is configured with VNI = VID.
The Default VLAN is excluded to avoid a potential default distribution of untagged L2 traffic over a wide network.

VLAN names that follow the Special VLAN Names format will continue to create VNI = <vni> specified in the name.

EXOS Command Line
=================
ezvxlan.py is managed using the ``run script`` CLI command.

Help
----
To see the ezvxlan options, enter

.. code-block:: bash

    # run script ezvxlan.py -h
    usage: ezvxlan [-h] [-d] {start,stop,restart,show} ...

    positional arguments:
      {start,stop,restart,show}
        start               Start the ezvxlan application
        stop                Stop the ezvxlan application
        restart             Restart the ezvxlan application. Useful after upgrade
        show                Show the running status of ezvxlan.

    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           Enable debug


start help
----------
.. code-block:: bash

    # run script ezvxlan.py start -h
    usage: ezvxlan start [-h] [-p PORT] [--fabric | --allvlans]

    optional arguments:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  Controller port. Always add this port when VXLAN VLANs
                            are created
      --fabric              Extreme Fabric mode. When Fabric is enabled, auto
                            create VxLAN VNIs for all VLANs
      --allvlans            Automatically create VxLAN VNIs for all VLANs except
                            default. VNI = VID

no option
    If no additional ``start`` option is specified, ezvxlan.py looks for `Special VLAN Names`_.

``--port``
    When a VLAN is created dynamically, (e.g. with VMware) it may be desireable to always add a constant port to the VLAN, like an uplink port.

``--fabric``
    When Extreme Fabric is enabled, and the desired ezvxlan.py behavior is to automatically create VXLAN VNIs for all non-fabric VLANs, add this option to the start commnad. If Extreme Fabric is not enabled, ezvxlan.py behaves as if ``start`` was entered without any additional option.

``--allvlans``
    For simple VXLAN deployments where the L2 VLAN domain is the same across the network, this option will automatically create a VXLAN VNI for any VLAN created. The VNI is set to the VLAN id.

start
-----
.. code-block:: bash

    # run script ezvxlan.py start
    # run script ezvxlan.py start --fabric
    # run script ezvxlan.py start --allvlans

    Starting ezvxlan

stop help
---------
.. code-block:: bash

    # run script ezvxlan.py stop -h
    usage: ezvxlan stop [-h] [-k]

    optional arguments:
      -h, --help  show this help message and exit
      -k, --keep  Keep automatically created VXLAN VNIs with names that start with SYS_VN_

no option
    stop ezvxlan.py.  All automatically created VNI's beginning with SYS_VN\_ are removed. Because ezvxlan.py is no longer running, no automatic VNI creation/deletion will be performed.

``--keep``
    stop ezvxlan.py and leave any automatically created VNI's in place. Because ezvxlan.py is no longer running, no automatic VNI creation/deletion will be performed.

stop
----
.. code-block:: bash

    # run script ezvxlan.py stop
    Stopping ezvxlan
    Deleting VXLAN VNI names starting with SYS_VN_

.. code-block:: bash

    # run script ezvxlan.py stop --keep
    Stopping ezvxlan
    Keeping VXLAN VNI names starting with SYS_VN_

show
----
.. code-block:: bash

    # run script ezvxlan.py show
    ezvxlan Version: 2.0.0.3 process is running
    VLANs with names SYS_VLAN_xxxx or VNI_<vni><text> are automatically mapped to SYS_VN_<vni> VTEPs

or

.. code-block:: bash

    # run script ezvxlan.py show
    ezvxlan Version: 1.0.0.6        process is not running
    VLANs with names SYS_VLAN_xxxx or VNI_<vni><text> are not mapped to SYS_VN_<vni> VTEPs automatically


Application Solutions
=====================
The usage described below are potential solutions where ezvxlan.py contributes.

# A low end/low cost VMware NSX alternative
# Interoperabity with Open Stack
# Interoperability with Extreme Fabric
# Automatic large scale L2 domain

These solutions are describe in their corresponding solutions document and are only included here for reference.


VMware NSX Alternative
----------------------
In this first environment, the EXOS vm-tracking feature is enabled with dynamic vlan support. The vm-tracking feature interacts with Extreme Control via RADIUS to validate MAC address/VLANs on a port. When the MAC address is validated, vm-tracking creates a VLAN with the name:

* SYS_VLAN_nnnn where nnnn is the VLAN tag
* The ezvxlan.py application creates a corresponding VXLAN VNI with the same number as the VLAN tag

.. figure::  appVMwareRefDiag.png
    :figclass: vmware
    :align: center

.. centered:: Low End/Low Cost VMware NSX Alternative

Interoperability with Open Stack
--------------------------------
    
The second application environment involves Open Stack. Open Stack interacts with Extreme Control to create a VLAN with the name format:

*   VNI-<vni><something> via SNMP.
*   The ezvxlan.py application extracts the <vni> portion and creates a VXLAN VNI with the name
    *   SYS_VN_<vni> where <vni> is a minimum 4 digit, zero filled number. E.g. 0006. The <vni> can grow to as many digits beyond 4 that are necessary.

.. figure::  appOpenStackRefDiag.png
    :figclass: openstack
    :align: center

.. centered:: Interoperability with Open Stack

