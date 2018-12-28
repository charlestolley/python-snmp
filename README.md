# Overview
I began work on this project in late 2017 or early 2018 in hopes of making a library that is easy and _intuitive_ to use. I worked through multiple preliminary drafts throughout 2018, scrapping each when I discovered shortcomings inherent in the design. The GitHub repository contains a `notes.txt` file, in which I documented my thoughts as I worked through the several iterations. In short, I find the most popular libraries to be unnecessarily complex or even buggy, (I must say, however, that I actually find Snimpy to be quite elegant, and any slight distaste I have for it is probably a sign that I think too much like a C programmer). I have decided to publish this package in its infancy, both to motivate myself to continue to improve it, and to encourage other budding contributors to the open source community to tear it apart and make it better. I have found myself frustrated in my attempts to contribute to other projects because they were simply too large for me to wrap my head around. Hopefully, such a small, simple project will become a magnet for others like me who want to contribute.

This package is written specifically for Python 3. There is no guarantee of correct operation for Python 2.

### Version 0.0.1
This version constitutes a minimum viable product in the truest sense. It is hard-coded to support only unauthenticated SNMPv1 on UDP port 161, but the structure of the software is hopefully flexible enough that it can be massaged into supporting more recent versions as well. All OID's must be provided as dot-separated numbers, as there is no support for parsing MIB files. As indicated in the `notes.txt` file, basic operation is seen as a priority. Fancier features will hopefully be available in future releases.

Usage is meant to be quite simple. All requests are handled by an object of type `Manager`, and return an object of type `VarBindList`. This object contains entries of type `VarBind`, which may be accessed by numerical indices or by iteration. `VarBind` objects have two attributes: `name`, which is an `OID` object, and `value`, which may be any type. All of the aforementioned types (with the exception of the `Manager`) are defined in `snmp.types`, and inherit from a base class called `ASN1`. `INTEGER`, `OCTET_STRING`, `NULL`, and `OID` types, as well as any subclasses, are decoded into python primitives with the `.value` attribute. Note that `OCTET_STRING`s are always stored as `bytes`, and never as `str`, as this can cause `UnicodeDecodeError`s for non-ASCII data. The following example code retrieves IF-MIB::ifDescr.1 from localhost:

    from snmp import Manager

    manager = Manager()
    variable_list = manager.get("127.0.0.1", "1.3.6.1.2.1.2.2.1.2.1", community=b"public")
    oid = variable_list[0].name
    ifDescr = variable_list[0].value
    print("{}: {}".format(oid.value, ifDescr.value))

The output should look something like this:

    1.3.6.1.2.1.2.2.1.2.1: b'lo'
