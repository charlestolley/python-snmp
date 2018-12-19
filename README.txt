Features of an Ideal SNMP Package:

Basic:
the base-level implementation should be MIB-agnostic (deal only with numeric OIDs)
two possibilities for how to deal with type-checking:
    - allow arguments specifying the expected type for a particular variable
    - simply return an object of a class determined by the encoded response and leave
        type-checking to the caller
get/walk multiple OIDs in a single PDU (this is supported in the protocol, but I don't know of
    a package that does it)
raise useful errors, corresponding to the error messages in the responses
perhaps implement functions to asynchronously handle network communication, freeing up the
    main thread to do other things while waiting for a response
write the initial version in Python, but perhaps port to C later, or perhaps allow as a build
    option the choice between the Python and the C implementation
NOTE: though this should be designed to support Python 3, OCTET STRINGs should NEVER be
    represented as the native str type; use bytes or bytearray instead (or something similar)
    - this is one of my core gripes with netsnmp and easysnmp

Higher-level:
parse MIB files
ensure correct variable types
return native python types, allowing the user to opt for either a tuple or a dict
allow entire tables to be walked at once
    for example, ifTable is organized as follows, where a row corresponds to a single ifEntry:

    ifIndex     ifDescr     ifType      ifMtu       ifSpeed     ...
    --------------------------------------------------------------------
    1           lo          24          65536       10000000    ...
    26          vpn0        1           1406        0           ...
    112         Broadcom... 6           1500        0           ...
    113         Broadcom... 6           1500        0           ...

    Owing to the structure of these tables, a GetNextRequest will traverse the entire table
    lengthwise (column-major order in the above table) to get all ifIndex values before
    proceeding to ifDescr. The more natural way to view a table is to look at the ifIndex,
    ifDescr, ifType, etc straight across the row. The Basic section above mentions that a
    single PDU can contain multiple OIDs all together. It would be nice to have a feature to
    walk an entire table, fetching a full entry as a single request by including (ifIndex,
    ifDescr, ifType, ifMtu, ifSpeed, ...) all in a single PDU.

Icing on top:
Command line versions of all tools
It might be convenient to allow a user to create a config file for their community
    strings/credentials, organized by host, as well as the version that should be used to
    communicate with that host. It would make it so they did not have to manually include
    sensitive information in the command line, or put it in their code
perhaps it would be good to implement some sort of cache structured as an actual tree


Sample usage:

    import snmp

    ifIndex, ifDescr, ifType = snmp.get_next(
        "localhost",
        "1.3.6.1.2.1.2.2.1.1",
        "1.3.6.1.2.1.2.2.1.2",
        "1.3.6.1.2.1.2.2.1.3",
        version=snmp.v1,
        community="public"
    )

    print("ifIndex: {}({})".format(ifIndex.__class__.__name__, ifIndex))
    print("ifDescr: {}({})".format(ifDescr.__class__.__name__, ifDescr))
    print("ifType: {}({})".format(ifType.__class__.__name__, ifType))

    ...

    Expected Output:

        ifIndex: Integer32(1)
        ifDescr: OctetString(b'lo')
        ifType: Integer(24)

RFC 1157 points out that "effective management of administrative relationships [...] requires authentication services that [...] are able to identify authentic SNMP messages [...]. Some SNMP implementations may wish to support only a trivial authentication service that identifies all SNMP messages as authentic SNMP messages". Perhaps there should be a way to register a function to perform authentication. This is certainly icing on the cake, as it will likely never actually be used, but the Manager can be designed to keep in mind that this may one day be implemented.

Here are some notes I wrote a while back that I can't be bothered to look at or edit right now

VariableBinding:
    create Variable Binding with no value

GetRequest:
    send the request and return a list of Variable Binding objects
    return a list of VariableBinding objects in the same order
    if they come back in the wrong order, raise a Protocol Exception, but have the out of order list as an attribute of the exception so they can still recover from it
    if the error status is set, raise the corresponding exception, each of which should inherit from a parent class, and the class should have the appropriate name, and a field containing the error status code. The error message should be the offending OID



Process:
# factory -- version will dictate what type to return
SNMP(version, community, rw_community)  # this will contain a network communicator -- default to UDP socket, but loosely coupled so it can be changed

User calls SNMP.get(host, oid, oid, oid ...)
    type = get_request
    call request(type, host, community, oids)
        call construct_pdu(type, oids) # doesn't set request id field
        call send(host, community, pdu)
            sets request id
            sets community
            serializes packet
            communicator.request
            unwrap first layer
            - check version
            - check community
            unwrap second layer
            - check request id

            check errors
            return pdu object

pdu class
    request id (integer)
    type (integer)
    vars (list)

decode(string, count=0)
    # count zero means unpack until leftovers = ""
    items = []
    while (string)
        if items and len(items) == count
            raise encoding error (more items than expected)
        decode type
        decode length
        obj, string = first (length) bytes of string, leftovers
        items.append( (type, obj) )
        if string

    if count and len(items) != count
        raise encoding error (less items than expected)

    return items
