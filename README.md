## Introduction
I have rewritten this library entirely since version 0.1.7, the last published version. The idea behind versions 0.1.x was to support SNMPv1 first, and then add support for SNMPv2c and SNMPv3 later. I decided some time ago that it would probably be better to take the opposite approach. This latest version (which I hope to soon release as v0.2.0) currently supports only SNMPv3. I plan to eventually add support for SNMPv1 and SNMPV2c, and I believe the current design is flexible enough that that should be pretty straightforward. This library is only suited to perform the role of a "manager" (more specifically, it can act as a Command Generator, not a Notification Receiver). One day it may support other roles.
## Usage Overview
The conceptual model for using this library is to create a single Engine instance, and then call the Engine.Manager() factory function to instantiate a manager object for each remote SNMP engine. Each manager object defines methods for each type of request (Get, GetNext, Set, and GetBulk). By default, each request will block until a response has been received, in which case the return value will be a ResponsePDU instance. The manager can also be configured to return a request handle object without blocking (or it can be configured for a single request). This allows multiple requests to be in-flight at once. To access the response, call the wait() method of the request handle, which may block, and which returns a ResponsePDU.

User-based security is managed through the Engine object. The addUser method allows you to specify an authentication protocol, authentication secret, privacy protocol, and privacy secret for each user name. There is a possibility, however, that you may have multiple agents that use the same user name with different security configurations. To account for this possibility, the addUser function accepts a "namespace" parameter. The default namespace is identified by the empty string (""), but you may provide alternate credentials for a duplicate user name by providing a unique namespace identifier string. The namespace identifier must also be provided to the Manager() factory function, so that it can select the correct credentials for the remote engine that it manages.

There are plenty of other features to cover in some of the lower level classes. Thorough documentation is one of my main requirements before I am willing to bump the version to 1.0.0. For now, I will just mention that the snmp.types.OID type is meant to make it simple to interpret object indices, both to simplify "walk" operations, and to make it easy to correlate related MIB objects that use the same index. For example, you can create an OID object for ifDescr by calling `OID.parse(".1.3.6.1.2.1.2.2.1.2")`. Then, to process the result of a GetNext operation, call the `extractIndex()` method of the OID object for the variable binding as follows:

    try:
        index = varbind.name.extractIndex(ifDescr, Integer)
    except OID.BadPrefix:
        # object is not an instance of ifDescr
    except OID.IndexDecodeError:
        # the OID could not be properly parsed using
        # the type(s) you provided to extractIndex
    else:
        print(f"ifDescr.{index.value} = \"{varbind.value.data.decode()}\"")

The output should look like this (assume interface 1 is named "loopback"):

    ifDescr.1 = "loopback"

## Working Example

    from snmp.engine import Engine
    from snmp.security.usm.auth import *
    from snmp.security.usm.priv import *
    from snmp.types import *

    sysDescr = OID.parse("1.3.6.1.2.1.1.1")
    ifDescr = OID.parse("1.3.6.1.2.1.2.2.1.2")

    # autowait=False will cause each request to return a handle rather than blocking
    with Engine(autowait=False) as engine:
        engine.addUser(
            "sample-user",
            authProtocol=HmacSha256,
            authSecret=b"sample-auth-secret",
            privProtocol=Aes128Cfb,
            privSecret=b"sample-priv-secret",
        )

        # you can use autowait=True/False when creating a Manager
        hostA = engine.Manager("192.168.0.1")
        hostB = engine.Manager("192.168.0.2", autowait=True)

        # you can use wait=True/False on any single request as well
        requestA = hostA.get(sysDescr.extend(0))
        requestB = hostB.getBulk(ifDescr, maxRepetitions=4, wait=False)

        responseA = requestA.wait()
        varbind = responseA.variableBindings[0]
        print(f"{varbind.name} = \"{varbind.value.data.decode()}\"")

        responseB = requestB.wait()

        # quasi-infinite loop with a safety valve
        for i in range(100):
            for varbind in responseB.variableBindings:
                oid, value = varbind

                try:
                    ifIndex = oid.extractIndex(ifDescr, Integer)
                except OID.BadPrefix:
                    break

                print(f"ifDescr.{ifIndex.value} = \"{value.data.decode()}\"")
            else:
                responseB = hostB.getBulk(oid, maxRepetitions=4)
                continue

            break
## Installation Notes
The USM privacy module depends on OpenSSL. Windows wheels use statically linked libraries so you should be able to install `python-snmp` without the need to install OpenSSL. If a wheel is not available for your platform, you will need the following environment variables to allow pip to build the sdist:

    set CL="-I<path-to-OpenSSL>\include"
    set LINK="/LIBPATH:<path-to-OpenSSL>\lib"

It is also possible to use `python-snmp` without OpenSSL if you do not need to use the USM privacy features. However, you will need to tweak setup.py to get it to install. Clone this directory, remove the `cffi_modules` argument to setup in `setup.py`, and then call `pip install <path-to-clone>`.
