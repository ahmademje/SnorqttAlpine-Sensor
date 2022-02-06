import random
import socket

from require.libs.snort_parser import mac_address, ip_to_str, ip6_to_str, get_protocol_from_id, \
    get_ip_detail_from_ethernet_data, get_snort_message, list_protocol


def test_mac_address():
    assert mac_address(b't\xc6;\xc9S_') == '74:c6:3b:c9:53:5f'


def test_ip_to_str():
    ipv4_address_str = '192.168.56.103'
    ipv4_address_bytes = socket.inet_pton(socket.AF_INET, ipv4_address_str)

    assert ip_to_str(ipv4_address_bytes) == ipv4_address_str


def test_ip6_to_str():
    ipv6_address_str = '2001:db8:3333:4444:5555:6666:7777:8888'
    ipv6_address_bytes = socket.inet_pton(socket.AF_INET6, ipv6_address_str)

    assert ip6_to_str(ipv6_address_bytes) == ipv6_address_str


def test_get_protocol_from_id_145_must_true():
    test_protocol_id = list_protocol[145]

    assert get_protocol_from_id(255) == test_protocol_id  # true


def test_get_protocol_from_id_145_must_false():
    test_protocol_id = list_protocol[145]

    assert get_protocol_from_id(250) != test_protocol_id  # false


def test_get_protocol_from_id_144_must_true():
    protocol_id = random.randint(253, 254)
    test_protocol_id = list_protocol[144]

    assert get_protocol_from_id(protocol_id) == test_protocol_id  # true


def test_get_protocol_from_id_144_must_false():
    protocol_id = random.randint(1, 200)
    test_protocol_id = list_protocol[144]

    assert get_protocol_from_id(protocol_id) != test_protocol_id  # false


def test_get_protocol_from_id_143_must_true():
    protocol_id = random.randint(143, 252)
    test_protocol_id = list_protocol[143]

    assert get_protocol_from_id(protocol_id) == test_protocol_id  # true


def test_get_protocol_from_id_143_must_false():
    protocol_id = random.randint(1, 142)
    test_protocol_id = list_protocol[143]

    assert get_protocol_from_id(protocol_id) != test_protocol_id  # false


def test_get_ip_detail_from_ethernet_data():
    # TODO: create unit test for get_ip_detail_from_ethernet_data() function
    pass


def test_get_snort_message():
    # TODO: create unit test for get_snort_message() function
    pass
