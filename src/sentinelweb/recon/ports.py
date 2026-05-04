"""Port / service discovery via an nmap subprocess wrapper."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..scope.policy import ScopePolicy


class NmapError(RuntimeError):
    pass


@dataclass(frozen=True)
class Service:
    host: str
    port: int
    proto: str
    state: str
    service: str
    product: str = ""
    version: str = ""


def have_nmap() -> bool:
    return shutil.which("nmap") is not None


def scan(
    host: str,
    scope: ScopePolicy,
    *,
    ports: str = "80,443,8080,8443",
    extra_args: tuple[str, ...] = ("-sT", "-Pn", "-T3", "--max-retries", "1"),
) -> list[Service]:
    """Run nmap against ``host`` (which must be in scope)."""
    scope.assert_in_scope(host)
    if not have_nmap():
        raise NmapError("nmap binary not found in PATH")

    cmd = ["nmap", "-oX", "-", "-p", ports, *extra_args, host]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError("nmap timed out") from exc
    if completed.returncode != 0:
        raise NmapError(f"nmap exited {completed.returncode}: {completed.stderr.strip()}")
    return parse_xml(completed.stdout)


def parse_xml(xml: str) -> list[Service]:
    """Parse nmap -oX output into Service records."""
    if not xml.strip():
        return []
    out: list[Service] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NmapError(f"could not parse nmap XML: {exc}") from exc

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        host = addr_el.get("addr", "") if addr_el is not None else ""
        for p in host_el.findall(".//port"):
            state_el = p.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            svc_el = p.find("service")
            svc = svc_el.get("name", "") if svc_el is not None else ""
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            try:
                port = int(p.get("portid", "0"))
            except ValueError:
                continue
            out.append(
                Service(
                    host=host,
                    port=port,
                    proto=p.get("protocol", "tcp"),
                    state=state,
                    service=svc,
                    product=product,
                    version=version,
                )
            )
    return out
