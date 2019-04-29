# pylint: disable-all
from collections import namedtuple
import gcp_audit
from util.gcp import Gcp

from unittest.mock import MagicMock

import pytest

MockTuple = namedtuple('MockTuple', ['name', 'type_', 'info'])

def test_check_firewall_rules(mocker, monkeypatch):

    issue = "targets and/or ports open to all"
    link = ("https://console.cloud.google.com/"
            "networking/firewalls/details/test?project=infect-testing")

    def mock_fw():
        return [MockTuple(name='test',
                          type_='#firewall',
                          info={
                              'protocol': 'all',
                              'ranges': ['0.0.0.0/0'],
                              'ports': 'all'
                          }
                         )]

    gcp = Gcp()
    monkeypatch.setattr(gcp, 'project', value='infect-testing')
    monkeypatch.setattr(gcp, 'get_full_firewall_rules', mock_fw)
    monkeypatch.setattr(gcp_audit, 'LIST_OF_SHAME', value=[])
    mock_full_firewall_rules = mocker.patch.object(gcp, 'get_full_firewall_rules')
    mock_full_firewall_rules.return_value = mock_fw()
    event = gcp_audit.check_firewall_rules(gcp)

    assert gcp_audit.LIST_OF_SHAME == mock_fw()

def test_check_firewall_secure(mocker, monkeypatch):

    def mock_fw():
        return [MockTuple(name='test',
                          type_='#firewall',
                          info={
                              'protocol': 'icmp',
                              'ranges': ['0.0.0.0/0'],
                              'ports': 'all'
                          })]

    gcp = Gcp()
    monkeypatch.setattr(gcp, 'project', value='infect-testing')
    monkeypatch.setattr(gcp, 'get_full_firewall_rules', mock_fw)
    event = gcp_audit.check_firewall_rules(gcp)

    assert gcp_audit.LIST_OF_SHAME == []

def test_check_bucket_acl(mocker, monkeypatch):

    issue = 'Bucket set for allUsers access'

    def mock_acl():
        return [MockTuple(name='test_bucket',
                          type_='Bucket',
                          info={
                              'entity': 'allUsers',
                              'role': 'READER'
                          })]

    gcp = Gcp()
    monkeypatch.setattr(gcp, 'project', value='infect-testing')
    monkeypatch.setattr(gcp, 'get_all_bucket_acl', mock_acl)
    event = gcp_audit.check_bucket_acl(gcp)

    assert gcp_audit.LIST_OF_SHAME == mock_acl()

def test_check_objects_acl(mocker, monkeypatch):

    issue = 'Object set for allUsers access'

    def mock_obj_acl():
        return [MockTuple(name='test_object',
                          type_='Bucket Object',
                          info={
                              'oid': 'testId',
                              'entity':'allUsers',
                              'obj': 'test_object'
                          })]

    gcp = Gcp()
    monkeypatch.setattr(gcp, 'project', value='infect-testing')
    monkeypatch.setattr(gcp, 'get_all_objects_acls', mock_obj_acl)
    monkeypatch.setattr(gcp_audit, 'LIST_OF_SHAME', value=[])
    event = gcp_audit.check_objects_acl(gcp)

    assert gcp_audit.LIST_OF_SHAME == mock_obj_acl()
