__all__ = [
    "BulkPDUTest", "PDUTest", "SetRequestPduTest", "ResponsePduTest",
    "PDUClassesTest",
]

import re
import unittest

from snmp.exception import *
from snmp.ber import *
from snmp.pdu import *
from snmp.smi import *
from snmp.utils import subbytes

class PDUTest(unittest.TestCase):
    def setUp(self):
        self.oid = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)

    def test_constructor_treats_OIDs_and_OID_strings_the_same(self):
        self.assertEqual(
            GetRequestPDU(str(self.oid)),
            GetRequestPDU(self.oid),
        )

    def test_variableBindings_takes_precedence_over_positional_args(self):
        pdu = ResponsePDU(
            "the first of four nonsense arguments",
            1984,
            OID(1, 2, 3, 4, 5),
            unittest.main,
            variableBindings=VarBindList(self.oid),
        )

        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, self.oid)

    def test_iter_yields_requestID_errorStatus_errorIndex_varbinds(self):
        requestID = 24
        errorStatus = ErrorStatus(3)
        pdu = ResponsePDU(requestID=requestID, errorStatus=errorStatus)

        i = iter(pdu)
        self.assertEqual(next(i), Integer(requestID))
        self.assertEqual(next(i), Integer(errorStatus))
        self.assertEqual(next(i), Integer(0))
        self.assertEqual(next(i), VarBindList())
        self.assertRaises(StopIteration, next, i)

    def test_len_is_always_4(self):
        self.assertEqual(len(GetRequestPDU()), 4)

    def test_different_PDU_types_are_not_equal(self):
        self.assertNotEqual(GetRequestPDU(), GetNextRequestPDU())

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        pdu = ResponsePDU(
            VarBind(self.oid, OctetString(b"lo")),
            requestID=12,
            errorStatus=ErrorStatus.genErr,
            errorIndex=1,
        )

        self.assertEqual(eval(repr(pdu)), pdu)

    def test_decode_raises_ParseError_when_errorStatus_is_invalid(self):
        encoding = bytes.fromhex("a0 0b 02 01 00 02 01 13 02 01 00 30 00")

        try:
            GetRequestPDU.decodeExact(encoding)
        except ParseError as err:
            self.assertEqual(err.data, subbytes(encoding, start=5, stop=8))
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_decode_raises_ParseError_on_negative_errorIndex(self):
        encoding = bytes.fromhex("a0 0b 02 01 00 02 01 01 02 01 ff 30 00")

        try:
            GetRequestPDU.decodeExact(encoding)
        except ParseError as err:
            self.assertEqual(err.data, subbytes(encoding, start=8, stop=11))
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_decode_raises_ParseError_if_errorIndex_is_out_of_range(self):
        encoding = bytes.fromhex("a0 0b 02 01 00 02 01 01 02 01 01 30 00")

        try:
            GetRequestPDU.decodeExact(encoding)
        except ParseError as err:
            self.assertEqual(err.data, subbytes(encoding, start=8, stop=11))
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_decode_ignores_errorIndex_if_errorStatus_is_zero(self):
        encoding = bytes.fromhex("a0 0b 02 01 00 02 01 00 02 01 04 30 00")
        pdu = GetRequestPDU.decodeExact(encoding)

    def test_the_result_of_decode_encode_equals_the_original_object(self):
        pdu = GetRequestPDU(self.oid)
        self.assertEqual(GetRequestPDU.decodeExact(pdu.encode()), pdu)

    def test_withRequestID_returns_new_PDU_of_the_same_type(self):
        getPDU = GetRequestPDU(self.oid)
        getNextPDU = GetNextRequestPDU(self.oid)
        setPDU = SetRequestPDU(VarBind(self.oid, Integer(4)))

        self.assertIsInstance(getPDU.withRequestID(328), GetRequestPDU)
        self.assertIsInstance(getNextPDU.withRequestID(329), GetNextRequestPDU)
        self.assertIsInstance(setPDU.withRequestID(330), SetRequestPDU)

    def test_withRequestID_copies_all_fields_except_requestID(self):
        pdu = GetRequestPDU(
            self.oid,
            errorStatus=ErrorStatus.tooBig,
            errorIndex=1,
        )

        request = pdu.withRequestID(339)
        self.assertEqual(pdu.variableBindings, request.variableBindings)
        self.assertEqual(pdu.errorStatus, request.errorStatus)
        self.assertEqual(pdu.errorIndex, request.errorIndex)

    def test_withRequestID_does_not_modify_the_original_object(self):
        pdu = GetRequestPDU(self.oid)
        request = pdu.withRequestID(346)
        self.assertEqual(pdu.requestID, 0)

    def test_checkResponse_does_nothing_if_validResponse(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=382)
        response = ResponsePDU(
            VarBind("1.3.6.1.2.1.1.1.0", OctetString(b"description")),
            requestID=382,
        )

        request.checkResponse(response)

    def test_checkResponse_raises_ImproperResponse_if_not_validResponse(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=388)
        response = ResponsePDU(
            VarBind("1.2.3.4.5.6", Integer(123456)),
            requestID=388,
        )

        self.assertRaises(ImproperResponse, request.checkResponse, response)

class BulkPDUTest(unittest.TestCase):
    def setUp(self):
        self.oid = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)

    def test_raise_ValueError_if_nonRepeaters_is_negative(self):
        self.assertRaises(
            ValueError,
            GetBulkRequestPDU,
            self.oid,
            nonRepeaters=-1,
        )

    def test_raise_ValueError_if_maxRepetitions_is_negative(self):
        self.assertRaises(
            ValueError,
            GetBulkRequestPDU,
            self.oid,
            maxRepetitions=-1,
        )

    def test_variableBindings_takes_precedence_over_positional_args(self):
        pdu = GetBulkRequestPDU(
            "nonsense argument for BulkPDU",
            variableBindings=VarBindList(self.oid),
        )

        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, self.oid)

    def test_iter_yields_requestID_nonRepeaters_maxRepetitions_varbinds(self):
        requestID = 24
        nonRepeaters = 3
        pdu = GetBulkRequestPDU(
            "1.3.6.1.2.1.1.1",
            "1.2.3.4.5.5",
            "1.3.6.1.2.1.2.2.1.2",
            requestID=requestID,
            nonRepeaters=nonRepeaters,
        )

        i = iter(pdu)
        self.assertEqual(next(i), Integer(requestID))
        self.assertEqual(next(i), Integer(nonRepeaters))
        self.assertEqual(next(i), Integer(1))
        self.assertEqual(next(i), pdu.variableBindings)
        self.assertRaises(StopIteration, next, i)

    def test_len_is_always_4(self):
        self.assertEqual(len(GetBulkRequestPDU()), 4)

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        pdu = GetBulkRequestPDU(
            self.oid,
            requestID=12,
            nonRepeaters=1,
            maxRepetitions=4,
        )

        self.assertEqual(eval(repr(pdu)), pdu)

    def test_decode_raises_ParseError_if_nonRepeaters_is_negative(self):
        encoding = bytes.fromhex("a5 0b 02 01 00 02 01 ff 02 01 00 30 00")

        try:
            GetBulkRequestPDU.decodeExact(encoding)
        except ParseError as err:
            self.assertEqual(err.data, subbytes(encoding, start=5, stop=8))
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_decode_raises_ParseError_if_maxRepetitions_is_negative(self):
        encoding = bytes.fromhex("a5 0b 02 01 00 02 01 00 02 01 ff 30 00")

        try:
            GetBulkRequestPDU.decodeExact(encoding)
        except ParseError as err:
            self.assertEqual(err.data, subbytes(encoding, start=8, stop=11))
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_the_result_of_decode_encode_equals_the_original_object(self):
        pdu = GetBulkRequestPDU(self.oid, maxRepetitions=4)
        self.assertEqual(GetBulkRequestPDU.decodeExact(pdu.encode()), pdu)

    def test_withRequestID_returns_new_PDU_of_the_same_type(self):
        pdu = GetBulkRequestPDU(self.oid)
        self.assertIsInstance(pdu.withRequestID(401), GetBulkRequestPDU)

    def test_withRequestID_copies_all_fields_except_requestID(self):
        pdu = GetBulkRequestPDU(
            "1.3.6.1.2.1.1.1",
            "1.2.3.4.5.5",
            "1.3.6.1.2.1.2.2.1.2",
            nonRepeaters=2,
            maxRepetitions=4,
        )

        request = pdu.withRequestID(410)
        self.assertEqual(pdu.variableBindings, request.variableBindings)
        self.assertEqual(pdu.nonRepeaters, request.nonRepeaters)
        self.assertEqual(pdu.maxRepetitions, request.maxRepetitions)

    def test_withRequestID_does_not_modify_the_original_object(self):
        pdu = GetBulkRequestPDU(self.oid)
        request = pdu.withRequestID(417)
        self.assertEqual(pdu.requestID, 0)

    def test_all_tags_match_rfc_3416(self):
        suffix = bytes.fromhex("0b 02 01 00 02 01 00 02 01 00 30 00")
        GetRequestPDU       .decodeExact(b"\xa0" + suffix)
        GetNextRequestPDU   .decodeExact(b"\xa1" + suffix)
        ResponsePDU         .decodeExact(b"\xa2" + suffix)
        SetRequestPDU       .decodeExact(b"\xa3" + suffix)
        GetBulkRequestPDU   .decodeExact(b"\xa5" + suffix)
        InformRequestPDU    .decodeExact(b"\xa6" + suffix)
        SNMPv2TrapPDU       .decodeExact(b"\xa7" + suffix)
        ReportPDU           .decodeExact(b"\xa8" + suffix)

    def test_checkResponse_does_nothing_if_validResponse(self):
        request = GetBulkRequestPDU("1.3.6.1.2.1.1.1", nonRepeaters=1)
        response = ResponsePDU(
            VarBind("1.3.6.1.2.1.1.1.0", OctetString(b"description")),
        )

        request.checkResponse(response)

    def test_checkResponse_raises_ImproperResponse_if_not_validResponse(self):
        request = GetBulkRequestPDU("1.3.6.1.2.1.1.1", nonRepeaters=1)
        response = ResponsePDU(
            VarBind("1.2.3.4.5.6", Integer(123456)),
        )

        self.assertRaises(ImproperResponse, request.checkResponse, response)

class SetRequestPduTest(unittest.TestCase):
    def test_constructor_converts_tuples_to_VarBinds(self):
        pdu = SetRequestPDU(("1.2.3.4.5.6", Integer(123456)))
        self.assertEqual(len(pdu.variableBindings), 1)
        self.assertEqual(pdu.variableBindings[0].name, OID(1,2,3,4,5,6))
        self.assertEqual(pdu.variableBindings[0].value, Integer(123456))

class ResponsePduTest(unittest.TestCase):
    def test_checkErrorStatus_returns_for_noError(self):
        request = GetNextRequestPDU("1.3.6.1.2.1.1.1", requestID=482)
        response = ResponsePDU(
            VarBind("1.3.6.1.2.1.1.1.0", OctetString(b"description")),
            errorStatus=ErrorStatus.noError,
            errorIndex=0,
            requestID=482,
        )

        response.checkErrorStatus(request)

    def test_checkErrorStatus_raises_NoSuchName_for_noSuchName(self):
        request = GetNextRequestPDU("1.3.6.1.2.1.1.1", requestID=482)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1",
            errorStatus=ErrorStatus.noSuchName,
            errorIndex=1,
            requestID=482,
        )

        self.assertRaises(NoSuchName, response.checkErrorStatus, request)

    def test_NoSuchName_is_an_ErrorResponse_with_noSuchName_status(self):
        request = GetNextRequestPDU("1.3.6.1.2.1.1.1", requestID=504)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1",
            errorStatus=ErrorStatus.noSuchName,
            errorIndex=1,
            requestID=504,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.status, ErrorStatus.noSuchName)
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

    def test_checkErrorStatus_ErrorResponse_has_the_correct_errorStatus(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=521)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1.0",
            errorStatus=ErrorStatus.noAccess,
            errorIndex=1,
            requestID=521,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.status, ErrorStatus.noAccess)
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

    def test_checkErrorStatus_clamps_down_on_out_of_range_errorIndex(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=538)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1.0",
            errorStatus=ErrorStatus.noAccess,
            errorIndex=2,
            requestID=538,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.index, 1)
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

    def test_ErrorResponse_variableBindings_come_from_request(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=555)
        response = ResponsePDU(
            "1.2.3.4.5.6",
            errorStatus=ErrorStatus.noAccess,
            errorIndex=1,
            requestID=555,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.variableBindings, request.variableBindings)
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

    def test_ErrorResponse_oid_is_a_shortcut_to_index_variableBindings(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=555)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1.0",
            errorStatus=ErrorStatus.noAccess,
            errorIndex=1,
            requestID=555,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.oid, OID(1,3,6,1,2,1,1,1,0))
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

    def test_ErrorResponse_oid_is_None_if_errorIndex_is_zero(self):
        request = GetRequestPDU("1.3.6.1.2.1.1.1.0", requestID=555)
        response = ResponsePDU(
            "1.3.6.1.2.1.1.1.0",
            errorStatus=ErrorStatus.tooBig,
            errorIndex=0,
            requestID=555,
        )

        try:
            response.checkErrorStatus(request)
        except ErrorResponse as err:
            self.assertEqual(err.oid, None)
        else:
            errmsg = "ErrorResponse not raised by checkErrorStatus"
            raise AssertionError(errmsg)

# see RFC 3411 section 2.8 (pp. 13-14)
class PDUClassesTest(unittest.TestCase):
    def test_only_Get_GetNext_and_GetBulk_belong_to_the_Read_class(self):
        self.assertTrue (GetRequestPDU().       READ_CLASS)
        self.assertTrue (GetNextRequestPDU().   READ_CLASS)
        self.assertFalse(ResponsePDU().         READ_CLASS)
        self.assertFalse(SetRequestPDU().       READ_CLASS)
        self.assertTrue (GetBulkRequestPDU().   READ_CLASS)
        self.assertFalse(InformRequestPDU().    READ_CLASS)
        self.assertFalse(SNMPv2TrapPDU().       READ_CLASS)
        self.assertFalse(ReportPDU().           READ_CLASS)

    def test_only_Set_belongs_to_the_Write_class(self):
        self.assertFalse(GetRequestPDU().       WRITE_CLASS)
        self.assertFalse(GetNextRequestPDU().   WRITE_CLASS)
        self.assertFalse(ResponsePDU().         WRITE_CLASS)
        self.assertTrue (SetRequestPDU().       WRITE_CLASS)
        self.assertFalse(GetBulkRequestPDU().   WRITE_CLASS)
        self.assertFalse(InformRequestPDU().    WRITE_CLASS)
        self.assertFalse(SNMPv2TrapPDU().       WRITE_CLASS)
        self.assertFalse(ReportPDU().           WRITE_CLASS)

    def test_only_ResponsePDU_and_ReportPDU_belong_to_the_Response_class(self):
        self.assertFalse(GetRequestPDU().       RESPONSE_CLASS)
        self.assertFalse(GetNextRequestPDU().   RESPONSE_CLASS)
        self.assertTrue (ResponsePDU().         RESPONSE_CLASS)
        self.assertFalse(SetRequestPDU().       RESPONSE_CLASS)
        self.assertFalse(GetBulkRequestPDU().   RESPONSE_CLASS)
        self.assertFalse(InformRequestPDU().    RESPONSE_CLASS)
        self.assertFalse(SNMPv2TrapPDU().       RESPONSE_CLASS)
        self.assertTrue (ReportPDU().           RESPONSE_CLASS)

    def test_only_Trap_and_Inform_belong_to_the_Notification_class(self):
        self.assertFalse(GetRequestPDU().       NOTIFICATION_CLASS)
        self.assertFalse(GetNextRequestPDU().   NOTIFICATION_CLASS)
        self.assertFalse(ResponsePDU().         NOTIFICATION_CLASS)
        self.assertFalse(SetRequestPDU().       NOTIFICATION_CLASS)
        self.assertFalse(GetBulkRequestPDU().   NOTIFICATION_CLASS)
        self.assertTrue (InformRequestPDU().    NOTIFICATION_CLASS)
        self.assertTrue (SNMPv2TrapPDU().       NOTIFICATION_CLASS)
        self.assertFalse(ReportPDU().           NOTIFICATION_CLASS)

    def test_only_ReportPDU_is_Internal(self):
        self.assertFalse(GetRequestPDU().       INTERNAL_CLASS)
        self.assertFalse(GetNextRequestPDU().   INTERNAL_CLASS)
        self.assertFalse(ResponsePDU().         INTERNAL_CLASS)
        self.assertFalse(SetRequestPDU().       INTERNAL_CLASS)
        self.assertFalse(GetBulkRequestPDU().   INTERNAL_CLASS)
        self.assertFalse(InformRequestPDU().    INTERNAL_CLASS)
        self.assertFalse(SNMPv2TrapPDU().       INTERNAL_CLASS)
        self.assertTrue (ReportPDU().           INTERNAL_CLASS)

    def test_only_Get_GetNext_Set_GetBulk_and_Inform_are_Confirmed(self):
        self.assertTrue (GetRequestPDU().       CONFIRMED_CLASS)
        self.assertTrue (GetNextRequestPDU().   CONFIRMED_CLASS)
        self.assertFalse(ResponsePDU().         CONFIRMED_CLASS)
        self.assertTrue (SetRequestPDU().       CONFIRMED_CLASS)
        self.assertTrue (GetBulkRequestPDU().   CONFIRMED_CLASS)
        self.assertTrue (InformRequestPDU().    CONFIRMED_CLASS)
        self.assertFalse(SNMPv2TrapPDU().       CONFIRMED_CLASS)
        self.assertFalse(ReportPDU().           CONFIRMED_CLASS)

if __name__ == '__main__':
    unittest.main()
