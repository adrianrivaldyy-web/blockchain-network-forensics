#!/usr/bin/env python3
"""
Simulasi blockchain untuk menyimpan hash SHA-256 bukti jaringan PCAP.

Struktur folder yang diharapkan:
NIM_Nama/
├── evidence/
│   ├── PCAP01_NIM.pcap
│   ├── PCAP02_NIM.pcap
│   ├── PCAP03_NIM.pcap
│   ├── PCAP04_NIM.pcap
│   └── PCAP05_NIM.pcap
└── sourcecode/
    └── blockchain_pcap.py

Program ini hanya memakai Python Standard Library, sehingga tidak memerlukan
instalasi package tambahan melalui pip.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


EXPECTED_PCAPS: tuple[tuple[str, int], ...] = (
    ("PCAP01", 30),
    ("PCAP02", 50),
    ("PCAP03", 70),
    ("PCAP04", 90),
    ("PCAP05", 100),
)

ZERO_HASH = "0" * 64
CHUNK_SIZE = 1024 * 1024

PCAP_MAGIC_ENDIAN: dict[bytes, str] = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass
class EvidenceInfo:
    file_path: Path
    file_name: str
    expected_packet_count: int
    packet_count: int
    file_size_bytes: int
    sha256: str


@dataclass
class Block:
    index: int
    timestamp: str
    evidence_file: str
    packet_count: int
    evidence_hash: str
    previous_hash: str
    block_hash: str = ""

    def hash_payload(self) -> dict[str, object]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_file": self.evidence_file,
            "packet_count": self.packet_count,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
        }

    def calculate_hash(self) -> str:
        canonical_data = json.dumps(
            self.hash_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical_data).hexdigest()

    def seal(self) -> None:
        self.block_hash = self.calculate_hash()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_pcap_packets(file_path: Path) -> int:
    file_size = file_path.stat().st_size

    with file_path.open("rb") as file_obj:
        magic = file_obj.read(4)

        if magic == PCAPNG_MAGIC:
            raise ValueError(
                f"{file_path.name} masih berformat PCAPNG. "
                "Konversikan dengan editcap -F pcap, jangan hanya mengganti ekstensi."
            )

        endian = PCAP_MAGIC_ENDIAN.get(magic)
        if endian is None:
            raise ValueError(
                f"{file_path.name} bukan file PCAP klasik yang valid "
                f"(magic number: {magic.hex() or 'kosong'})."
            )

        remaining_global_header = file_obj.read(20)
        if len(remaining_global_header) != 20:
            raise ValueError(f"Global header {file_path.name} tidak lengkap.")

        packet_count = 0
        packet_header_format = f"{endian}IIII"

        while True:
            packet_header = file_obj.read(16)
            if packet_header == b"":
                break
            if len(packet_header) != 16:
                raise ValueError(
                    f"Packet header ke-{packet_count + 1} pada {file_path.name} "
                    "tidak lengkap."
                )

            _ts_sec, _ts_fraction, included_length, _original_length = struct.unpack(
                packet_header_format, packet_header
            )

            current_position = file_obj.tell()
            remaining_bytes = file_size - current_position
            if included_length > remaining_bytes:
                raise ValueError(
                    f"Data paket ke-{packet_count + 1} pada {file_path.name} "
                    "terpotong atau rusak."
                )

            file_obj.seek(included_length, os.SEEK_CUR)
            packet_count += 1

    return packet_count


def discover_evidence_files(evidence_dir: Path) -> tuple[str, list[tuple[Path, int]]]:
    if not evidence_dir.is_dir():
        raise FileNotFoundError(
            f"Folder evidence tidak ditemukan: {evidence_dir}\n"
            "Pastikan blockchain_pcap.py berada di folder sourcecode."
        )

    discovered: list[tuple[Path, int]] = []
    detected_nim: str | None = None

    for prefix, expected_count in EXPECTED_PCAPS:
        matches = sorted(evidence_dir.glob(f"{prefix}_*.pcap"))

        if not matches:
            raise FileNotFoundError(
                f"File {prefix}_NIM.pcap tidak ditemukan di folder evidence."
            )
        if len(matches) > 1:
            names = ", ".join(path.name for path in matches)
            raise ValueError(
                f"Ditemukan lebih dari satu file untuk {prefix}: {names}. "
                "Sisakan hanya satu file yang benar."
            )

        file_path = matches[0]
        nim = file_path.stem[len(prefix) + 1 :]
        if not nim:
            raise ValueError(f"NIM pada nama {file_path.name} tidak ditemukan.")

        if detected_nim is None:
            detected_nim = nim
        elif nim != detected_nim:
            raise ValueError(
                "NIM pada nama kelima file harus sama. "
                f"Ditemukan {detected_nim} dan {nim}."
            )

        discovered.append((file_path, expected_count))

    assert detected_nim is not None
    return detected_nim, discovered


def acquire_evidence_metadata(
    discovered_files: Iterable[tuple[Path, int]],
) -> list[EvidenceInfo]:
    evidence_list: list[EvidenceInfo] = []

    for file_path, expected_count in discovered_files:
        packet_count = count_pcap_packets(file_path)
        file_size = file_path.stat().st_size
        file_hash = calculate_sha256(file_path)

        evidence_list.append(
            EvidenceInfo(
                file_path=file_path,
                file_name=file_path.name,
                expected_packet_count=expected_count,
                packet_count=packet_count,
                file_size_bytes=file_size,
                sha256=file_hash,
            )
        )

    wrong_counts = [
        evidence
        for evidence in evidence_list
        if evidence.packet_count != evidence.expected_packet_count
    ]
    if wrong_counts:
        details = "\n".join(
            f"- {item.file_name}: ditemukan {item.packet_count}, "
            f"seharusnya {item.expected_packet_count} paket"
            for item in wrong_counts
        )
        raise ValueError(f"Jumlah paket belum sesuai ketentuan:\n{details}")

    return evidence_list


def create_blockchain(evidence_list: list[EvidenceInfo]) -> list[Block]:
    genesis = Block(
        index=0,
        timestamp=utc_timestamp(),
        evidence_file="GENESIS",
        packet_count=0,
        evidence_hash=ZERO_HASH,
        previous_hash=ZERO_HASH,
    )
    genesis.seal()

    blockchain = [genesis]

    for evidence in evidence_list:
        previous_block = blockchain[-1]
        block = Block(
            index=len(blockchain),
            timestamp=utc_timestamp(),
            evidence_file=evidence.file_name,
            packet_count=evidence.packet_count,
            evidence_hash=evidence.sha256,
            previous_hash=previous_block.block_hash,
        )
        block.seal()
        blockchain.append(block)

    return blockchain


def validate_blockchain(
    blockchain: list[Block], evidence_dir: Path, verify_files: bool = True
) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if len(blockchain) != 6:
        errors.append(
            f"Jumlah block salah: ditemukan {len(blockchain)}, seharusnya 6."
        )

    for position, block in enumerate(blockchain):
        if block.index != position:
            errors.append(
                f"Block posisi {position}: index tersimpan {block.index}, "
                f"seharusnya {position}."
            )

        recalculated_hash = block.calculate_hash()
        if block.block_hash != recalculated_hash:
            errors.append(
                f"Block {block.index}: block hash tidak sesuai hasil perhitungan ulang."
            )

        if position == 0:
            if block.previous_hash != ZERO_HASH:
                errors.append("Genesis block: previous hash harus 64 karakter nol.")
            if block.evidence_file != "GENESIS":
                errors.append("Genesis block: evidence file harus bernilai GENESIS.")
            continue

        expected_previous_hash = blockchain[position - 1].block_hash
        if block.previous_hash != expected_previous_hash:
            errors.append(
                f"Block {block.index}: previous hash tidak sama dengan "
                f"block hash milik block {position - 1}."
            )

        if verify_files:
            evidence_path = evidence_dir / block.evidence_file
            if not evidence_path.is_file():
                errors.append(
                    f"Block {block.index}: file bukti {block.evidence_file} tidak ditemukan."
                )
                continue

            try:
                actual_packet_count = count_pcap_packets(evidence_path)
                actual_evidence_hash = calculate_sha256(evidence_path)
            except (OSError, ValueError) as exc:
                errors.append(f"Block {block.index}: gagal membaca bukti: {exc}")
                continue

            if block.packet_count != actual_packet_count:
                errors.append(
                    f"Block {block.index}: packet count tersimpan "
                    f"{block.packet_count}, file saat ini {actual_packet_count}."
                )

            if block.evidence_hash != actual_evidence_hash:
                errors.append(
                    f"Block {block.index}: evidence hash berbeda dari SHA-256 file saat ini."
                )

    return not errors, errors


def format_size(size_bytes: int) -> str:
    return f"{size_bytes:,} bytes ({size_bytes / 1024:.2f} KiB)".replace(",", ".")


def render_hashing_result(nim: str, evidence_list: list[EvidenceInfo]) -> str:
    lines = [
        "=" * 78,
        "HASHING RESULT - SHA-256",
        "=" * 78,
        f"NIM terdeteksi : {nim}",
        "",
    ]

    for number, evidence in enumerate(evidence_list, start=1):
        lines.extend(
            [
                f"Evidence #{number}",
                f"Nama file     : {evidence.file_name}",
                f"Jumlah paket  : {evidence.packet_count}",
                f"Ukuran file   : {format_size(evidence.file_size_bytes)}",
                f"SHA-256       : {evidence.sha256}",
                "-" * 78,
            ]
        )

    return "\n".join(lines).rstrip()


def render_blockchain(blockchain: list[Block]) -> str:
    lines = [
        "=" * 78,
        "BLOCKCHAIN RESULT",
        "=" * 78,
    ]

    for block in blockchain:
        lines.extend(
            [
                f"BLOCK #{block.index}",
                f"Index          : {block.index}",
                f"Timestamp      : {block.timestamp}",
                f"Evidence File  : {block.evidence_file}",
                f"Packet Count   : {block.packet_count}",
                f"Evidence Hash  : {block.evidence_hash}",
                f"Previous Hash  : {block.previous_hash}",
                f"Block Hash     : {block.block_hash}",
                "-" * 78,
            ]
        )

    return "\n".join(lines).rstrip()


def render_validation_result(is_valid: bool, errors: list[str]) -> str:
    status = "VALID" if is_valid else "INVALID"
    lines = [
        "=" * 78,
        "VALIDATION RESULT",
        "=" * 78,
        f"Blockchain Validation : {status}",
    ]

    if errors:
        lines.append("")
        lines.append("Detail kesalahan:")
        lines.extend(f"- {error}" for error in errors)
    else:
        lines.extend(
            [
                "Previous Hash       : SESUAI",
                "Block Hash          : SESUAI",
                "Evidence Hash       : SESUAI",
                "Packet Count        : SESUAI",
                "Integritas Chain    : TERJAGA",
            ]
        )

    return "\n".join(lines)


def save_outputs(
    output_dir: Path,
    blockchain: list[Block],
    hashing_text: str,
    blockchain_text: str,
    validation_text: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "hashing_result.txt").write_text(hashing_text + "\n", encoding="utf-8")
    (output_dir / "blockchain_result.txt").write_text(
        blockchain_text + "\n", encoding="utf-8"
    )
    (output_dir / "validation_result.txt").write_text(
        validation_text + "\n", encoding="utf-8"
    )

    json_data = [asdict(block) for block in blockchain]
    (output_dir / "blockchain_output.json").write_text(
        json.dumps(json_data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hashing SHA-256 dan simulasi blockchain untuk lima file PCAP."
    )
    parser.add_argument(
        "--tamper-demo",
        action="store_true",
        help=(
            "Membuat salinan blockchain di memori, mengubah packet_count block 1, "
            "lalu menunjukkan bahwa validasi berubah menjadi INVALID."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    evidence_dir = project_root / "evidence"
    output_dir = script_dir / "output"

    try:
        nim, discovered_files = discover_evidence_files(evidence_dir)
        evidence_list = acquire_evidence_metadata(discovered_files)
        blockchain = create_blockchain(evidence_list)
        is_valid, validation_errors = validate_blockchain(blockchain, evidence_dir)

        hashing_text = render_hashing_result(nim, evidence_list)
        blockchain_text = render_blockchain(blockchain)
        validation_text = render_validation_result(is_valid, validation_errors)

        print(hashing_text)
        print("\n")
        print(blockchain_text)
        print("\n")
        print(validation_text)

        save_outputs(
            output_dir,
            blockchain,
            hashing_text,
            blockchain_text,
            validation_text,
        )

        print(f"\nFile output tersimpan di: {output_dir}")

        if args.tamper_demo:
            tampered_chain = copy.deepcopy(blockchain)
            tampered_chain[1].packet_count += 1
            tampered_valid, tampered_errors = validate_blockchain(
                tampered_chain, evidence_dir
            )
            print("\n")
            print("TAMPER DEMONSTRATION")
            print("-" * 78)
            print(render_validation_result(tampered_valid, tampered_errors))

        return 0 if is_valid else 1

    except (FileNotFoundError, PermissionError, OSError, ValueError) as exc:
        print("=" * 78, file=sys.stderr)
        print("PROGRAM BERHENTI KARENA DATA BELUM SESUAI", file=sys.stderr)
        print("=" * 78, file=sys.stderr)
        print(str(exc), file=sys.stderr)
        print("\nPeriksa kembali struktur folder, nama file, dan format PCAP.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
