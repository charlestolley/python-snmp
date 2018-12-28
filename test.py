#!/usr/bin/python3

import threading
from unittest import TestCase, main

from snmp import Manager
from snmp.exceptions import EncodingError
from snmp.types import length, unpack

class LengthTest(TestCase):
    def test_zero(self):
        self.assertEqual(length(0), b'\0')

    def test_short(self):
        self.assertEqual(length(0x7f), b'\x7f')

    def test_long(self):
        self.assertEqual(length(0x80), b'\x81\x80')

    def test_longer(self):
        self.assertEqual(length(0xffff), b'\x82\xff\xff')

    def test_longest(self):
        self.assertEqual(length(1234567890), b'\x84\x49\x96\x02\xd2')

class UnpackTest(TestCase):
    def test_empty(self):
        self.assertRaises(EncodingError, unpack, (b'',))

    def test_nolen(self):
        self.assertRaises(EncodingError, unpack, (b'\x30',))

    def test_leftovers(self):
        self.assertTupleEqual((2, b'\x01\x02', b'\x05\x00'), unpack(b'\x02\x02\x01\x02\x05\x00'))

    def test_short(self):
        self.assertRaises(EncodingError, unpack, (b'\x04\x01',))

    def test_bad_length(self):
        self.assertRaises(EncodingError, unpack, (b'\x04\x81',))

    def test_long(self):
        self.assertTupleEqual((4, b'\0' * 128, b''), unpack(b'\x04\x81\x80' + b'\0' * 128))

class ManagerTest(TestCase):
    def test_cleanup(self):
        m = Manager()
        del m
        self.assertEqual(threading.active_count(), 1)

main()
