import pytest
from app.capture.interface_manager import interface_manager


def test_interface_manager_discovery():
    ifaces = interface_manager.get_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    # At least one interface should have an IP or up status
    names = [i.name for i in ifaces]
    assert any("wi-fi" in n.lower() or "ethernet" in n.lower() or "loopback" in n.lower() for n in names)


def test_resolve_tshark_interface():
    dev_arg, friendly = interface_manager.resolve_tshark_interface("Wi-Fi")
    assert dev_arg is not None
    assert friendly is not None
