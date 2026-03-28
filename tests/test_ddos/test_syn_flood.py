"""Tests for the SYN flood simulation module."""

from __future__ import annotations

import sys
import types

from cybersim.ddos.syn_flood import SYNFloodAttack


class _FakePacket:
    def __init__(self, layer_name: str, **fields):
        self.layer_name = layer_name
        self.fields = fields

    def __truediv__(self, other):
        return (self, other)


def test_syn_flood_uses_fake_scapy_and_logs_completion(logger, monkeypatch):
    sent_packets = []

    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    fake_scapy_all.IP = lambda **kwargs: _FakePacket("IP", **kwargs)
    fake_scapy_all.TCP = lambda **kwargs: _FakePacket("TCP", **kwargs)
    fake_scapy_all.send = lambda packet, verbose=False: sent_packets.append((packet, verbose))
    fake_scapy.all = fake_scapy_all

    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy_all)

    attack = SYNFloodAttack(config={}, logger=logger)
    attack.run(target="127.0.0.1", port=8080, packet_count=2, rate_limit=0)

    assert len(sent_packets) == 2
    completed = logger.get_events(module="ddos_syn_flood", event_type="attack_completed")
    assert completed
    assert completed[-1]["details"]["packets_sent"] == 2


def test_syn_flood_stop_logs_event(logger):
    attack = SYNFloodAttack(config={}, logger=logger)
    attack.stop()

    stopped = logger.get_events(module="ddos_syn_flood", event_type="attack_stopped")
    assert stopped
