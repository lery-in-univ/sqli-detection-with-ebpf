"""BCC 기반 eBPF/XDP 로드 및 차단 목록 map 업데이트 모듈"""

from __future__ import annotations

import socket
import struct
from ctypes import c_uint32, c_ubyte
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]


class EbpfBlocker:
    def __init__(self, interface: str = "lo") -> None:
        self.interface = interface
        self.bpf = None
        self.blocked_ips = None
        self.xdp_flags = 0

    @property
    def ready(self) -> bool:
        return self.bpf is not None and self.blocked_ips is not None

    def start(self) -> None:
        try:
            from bcc import BPF
        except Exception as exc:
            print(f"[ebpf] BCC import 실패, eBPF 비활성화: {exc}")
            return

        program_path = ROOT_DIR / "src" / "ebpf" / "xdp_block.c"
        self.bpf = BPF(src_file=str(program_path))
        fn = self.bpf.load_func("xdp_block", BPF.XDP)
        self.xdp_flags = BPF.XDP_FLAGS_SKB_MODE
        self.bpf.attach_xdp(self.interface, fn, flags=self.xdp_flags)
        self.blocked_ips = self.bpf.get_table("blocked_ips")
        print(f"[ebpf] XDP attach 완료: {self.interface}")

    def stop(self) -> None:
        if self.bpf is None:
            return
        try:
            self.bpf.remove_xdp(self.interface, flags=self.xdp_flags)
            print(f"[ebpf] XDP detach 완료: {self.interface}")
        except Exception as exc:
            print(f"[ebpf] XDP detach 실패: {exc}")

    def block_ip(self, ip: str) -> None:
        if self.blocked_ips is None:
            print(f"[ebpf] eBPF 비활성화 상태, 차단 생략: {ip}")
            return

        key = c_uint32(struct.unpack("I", socket.inet_aton(ip))[0])
        self.blocked_ips[key] = c_ubyte(1)
        print(f"[ebpf] 차단 목록 추가: {ip}")
