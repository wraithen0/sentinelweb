from __future__ import annotations

from sentinelweb.recon import ports

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_xml_extracts_services() -> None:
    services = ports.parse_xml(SAMPLE_XML)
    by_port = {s.port: s for s in services}
    assert by_port[22].service == "ssh"
    assert by_port[22].product == "OpenSSH"
    assert by_port[80].state == "open"
    assert by_port[443].state == "closed"


def test_parse_empty_xml() -> None:
    assert ports.parse_xml("") == []
