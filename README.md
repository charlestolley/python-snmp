# Overview
I began work on this project in late 2017 or early 2018 in hopes of making a library that is easy and _intuitive_ to use. I worked through multiple preliminary drafts throughout 2018, scrapping each when I discovered shortcomings inherent in the design. The GitHub repository contains a `notes.txt` file, in which I documented my thoughts as I worked through the several iterations. In short, I find the most popular libraries to be unnecessarily complex or even buggy, (I must say, however, that I actually find Snimpy to be quite elegant, and any slight distaste I have for it is probably a sign that I think too much like a C programmer). I have found myself frustrated in my attempts to contribute to other projects because they were simply too large for me to wrap my head around, and so I decided simply to start from scratch.

This package is written specifically for Python 3. There is no guarantee of correct operation for Python 2.

### Version 0.1.x
This version maintains the minimalist spirit of previous versions. Currently only SNMPv1 is supported. There is no support for parsing MIB files, meaning that only numeric OIDs may be used.

Usage is meant to be quite simple. All requests are handled by a "Manager", which is created using the `snmp.Manager()` factory function. All requests return a list containing entries of type `VarBind`. `VarBind` objects have two attributes: `name`, which is an `OID` object, and `value`, which is one of several types representing ASN.1 data types. The `snmp.types` module defines a base class called `ASN1`, and several primitives: `INTEGER`, `OCTET_STRING`, `NULL`, `OID`, and `SEQUENCE`. Subclasses are defined for each of these according to the 'type' byte used in the ASN.1 encoding (`IpAddress`, `Counter32`, etc). These types may be decoded into python primitives with the `.value` attribute. Note that `OCTET_STRING`s will, by default, use `bytes`, rather than `str`. Within the rules of ASN.1, OCTET STRINGs may be used to represent non-ASCII data, and attempts to decode such data may unexpectedly cause `UnicodeDecodeError`s. The exception to this rule is the `IpAddress` subtype, which uses `socket.inet_ntoa` and `socket.inet_aton`, which turn a `bytes` object of length 4 into a `str`, and vice-versa.

#### Creating a Manager
The Manager object is created using the `Manager()` factory function. The only argument specific to this function is the `version` argument. Any other argument provided will be passed directly to the constructor of the Manager for that version. As of version 0.1.x, only version 1 is supported, meaning that the `version` parameter is not needed.

The SNMPv1 Manager has the following constructor prototype:

    __init__(self, community=None, rwcommunity=None, port=161, resend=1)

The `community` parameter will be used for all requests if the `rwcommunity` parameter is not provided. On the other hand, you may optionally provide the `rwcommunity` along with the `community` argument, in which case `rwcommunity` will be used for SET requests, and `community` will be used only for GET and GETNEXT requests.

`port` is the UDP port number to send requests to.

When a response is not received within a certain window after the request is sent, the manager will re-send the request until a longer timeout period has elapsed. The `resend` parameter dictates how many seconds to wait for a response before re-sending the original request, and may be a `float` or an `int`. The timeout parameter is not given in the constructor, but may be specified when the request is made, allowing different requests to have different timeout values.

#### Requests
SNMP version 1 supports only 3 types of request: GET, GETNEXT, and SET. A key design improvement introduced in version 0.1.0 of this package is the ability to send requests without blocking to wait for the response. As this feature is inconsistent with most other packages, the default behavior is for the request functions to block until the response is received, and then return the requested values. The details are mostly documented below in the section detailing the GET request, with additional notes made as needed in the other sections.

##### GET Request
GET requests are performed by calling the `get()` method on the Manager object. This method has the following prototype:

    get(self, host, *oids, community=None, block=True, timeout=10, refresh=False, next=False)

`host` is the __IPv4 Address__ of the target host. Hostnames or IPv6 addresses are not supported at this time.

`oids` allows for a variable number of OIDs to be requested at once. The return value of the function will be a list of `VarBind` objects, where the _ith_ element corresponds to the _ith_ OID. If `block` is `False`, a value of `None` in the returned list indicates that the value for that OID is not yet available.

`community` allows you to specify an alternate community string to use for this particular request. It is necessary only the first time an OID is requested from a particular host, or when `refresh` is `True`. For example, if an initial call is made where `block` is given as `False`, the given value of `community` will be used, but when the blocking call is made later to retrieve the value, `community` is not needed.

`block` may be set to `False` to cause the function to return immediately after the request has been sent, without waiting for the response. The value may be retrieved later by calling the function again, usually with `block` set to `True` (or ommitted). This is mostly useful only when a single manager will be used to talk to multiple hosts at once, allowing requests to be processed in parallel, rather than wasting time waiting for each in series.

`timeout` is the maximum number of seconds to wait for a response. If `block` is `True`, a `snmp.exceptions.Timeout` exception will be raised if a response is not received within that time. If `block` is `False`, no exception will be raised until the function is called again to get the response.

`refresh` will discard any previous values for the requested OIDs that have been stored locally. By default, no network traffic is sent to re-request the value of a variable except for the first request for that variable with a given Manager object, or when `refresh` is set to `True`. This should only be set at the time the request is to be sent, meaning that if `block` and `refresh` are both `True`, then when the later call is made to retrieve the value, `refresh` should be given as `False`, as the request has already been sent.

`next`: Setting this parameter to `True` will send a GETNEXT request, rather than a GET request. The `get_next()` function also exists, but is simply a wrapper function that calls `get()` with `next` set to `True`.

##### GETNEXT Request
As mentioned above, the GETNEXT request is actually implemented with the `get()` function. However, for sake of readability, a `get_next()` function is also provided. This function accepts all the same parameters as `get()`.

##### SET Request
SET requests are performed with the `set()` method, which has the following prototype:

    set(self, host, oid, value, community=None, block=True, timeout=10)

While the protocol does technically allow multiple SET operations to be performed in a single request, for simplicity, this function only supports setting a single variable at once, though this may change in the future. The `value` parameter may be a subtype of `ASN1`, but if it is given as a python native type, it will be automatically translated.

The `community` and `timeout` parameters work exactly as described above for `get()`.

The `block` parameter introduces some interesting considerations. By default, the function will block until the operation has returned successfully, and will return a list with a single entry for the VarBind contained in the response. On the other hand, if `block` is given as `False`, the function will return a value of None once the request has been sent, and the result should then be checked by a call to `get()` rather than making a second call to `set()`. Calling `set()` has the same effect as making a call to `get()` with `refresh` set to `True`, so the `get()` method is guaranteed not to return until the response for the SET request has been received.

In order to ensure data integrity, the Manager enforces what is essentially a writer preferred reader/writer policy between GET and SET requests. In other words, a SET request cannot be sent as long as there is an outstanding GET request that has not yet received a response. This means that even if `block` is given as `False`, the `set()` method may still block for a short time (up to the `timeout` for the outstanding GET request) before sending its request.

##### Walk Operation
As of version 0.1.4, a helper function is available to perform a simple walk. At the current time it only walks on a single variable at a time, but in the future it will be able to walk multiple variables in parallel. The function is implemented as a generator in order to improve responsiveness, but each step of the walk is performed as a blocking GETNEXT operation.

The function prototype is as follows:

    walk(self, host, oid, community=None, refresh=False, timeout=10)

#### Example

    import logging
    import time

    from snmp import Manager
    from snmp.exceptions import Timeout

    # uncomment this for verbose output
    #logging.basicConfig(level=logging.DEBUG)

    # REPLACE 'public' with your community string
    manager = Manager(b'public')

    try:
        hosts = ["10.0.0.2", "10.0.0.3"]                    # REPLACE these IPs with real IPs
        oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]   # [SNMPv2-MIB::sysDescr.0, SNMPv2-MIB::sysName.0]

        start = time.time()

        # removing this loop will increase run time on average
        for host in hosts:
            manager.get(host, *oids, block=False, timeout=1)
            manager.get(host, *oids, block=False, timeout=1, next=True)

        for host in hosts:
            vars = manager.get(host, *oids)
            print(host)
            for var in vars:
                print(var)

            vars = manager.get(host, *oids, next=True)
            for var in vars:
                print(var)

        end = time.time()
        print("Took {} seconds".format(end - start))

    except Timeout as e:
        print("Request for {} from host {} timed out".format(e, host))

    finally:
        manager.close()

__IMPORTANT:__ Manager objects must be closed when then are no longer needed (by calling `.close()`). Failure to do so may cause a program to hang rather than terminating properly.
