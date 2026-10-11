"""Pure-Python converter: pcap/pcapng of 802.11 traffic -> hashcat hc22000.

hcxtools (``hcxpcapngtool``) explicitly does not support Windows, so this module
implements the conversion natively. Two record types are produced:

* ``WPA*01*`` -- PMKID recovered from the RSN IE of EAPOL M1 (no monitor mode
  or packet injection required on the AP side, only a vulnerable AP).
* ``WPA*02*`` -- EAPOL key message pairs (M2/M3, M3/M4, M2/M4) with the MIC
  field of the second message, which is what hashcat mode 22000 verifies.

Link types handled: 127 (radiotap), 105 (bare 802.11), 1 (Ethernet),
127+ (LSB/ MSB radiotap variants are detected via the header length).
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from .options import normalize_bssid

# ---------------------------------------------------------------------------
# link types
# ---------------------------------------------------------------------------

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

# ---------------------------------------------------------------------------
# pcAP / pcapng readers
# ---------------------------------------------------------------------------

# Raw 4-byte file magic -> struct endianness for the rest of the header.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # microsecond, little endian
    b"\xa1\xb2\xc3\xd4": ">",  # microsecond, big endian
    b"\x4d\x3c\xb2\xa1": "<",  # nanosecond, little endian
    b"\xa1\xb2\x3c\x4d": ">",  # nanosecond, big endian
}

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_PB = 0x00000002
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006


class CaptureFormatError(ValueError):
    """The file is not a readable capture, rather than one holding no hashes.

    The two are different problems with different fixes, and collapsing them
    into "nothing found" is what makes this tool look deaf. A capture backend
    that gives up mid-run writes its error message *into the output file*
    rather than to stderr, so what reaches :func:`convert` is a short file
    containing text -- ``ERR: File is too big``, say -- which passes every
    "does it exist and is it non-empty" check and then parses as zero frames.
    Reported as an empty capture, that becomes "nobody reconnected during the
    capture" while the adapter in fact recorded the handshake and threw it away
    on the way to disk.
    """


def text_payload(data: bytes) -> str:
    """Return ``data`` as text when it is entirely printable, else ``""``.

    pcap and pcapng are binary formats by construction, so a file that reads as
    plain text was never a capture at all. The text is returned so the error can
    quote the capture tool's own words instead of guessing at them.
    """
    head = data[:200]
    if b"\x00" in head:
        return ""
    text = head.decode("utf-8", "replace").strip()
    return text if text and text.isprintable() else ""


def looks_like_capture(data: bytes) -> bool:
    """Whether ``data`` starts with a capture file signature.

    Checked wherever bytes arrive from somewhere that can fail quietly -- a
    serial board, a half-finished download -- because the alternative is a file
    named ``*.pcap`` holding an error message, which then reads as a capture
    that saw no handshake.
    """
    head = data[:4]
    return head in _PCAP_MAGICS or head == _SHB_BYTES


def _too_short(data: bytes) -> str:
    """Describe a file too small to be a capture."""
    text = text_payload(data)
    if text:
        return f"это не файл захвата, а текст: {text!r}"
    return f"файл слишком мал ({len(data)} байт) — захват не был дописан"


def _read_pcap(fh, size: int) -> Iterator[tuple[int, bytes]]:
    """Yield (linktype, frame_bytes) from a classic pcap file."""
    header = fh.read(24)
    if len(header) < 24:
        raise CaptureFormatError(_too_short(header))
    endian = _PCAP_MAGICS.get(header[:4])
    if endian is None:
        text = text_payload(header)
        raise CaptureFormatError(
            f"неизвестный формат файла захвата: {text!r}" if text
            else "неизвестный формат файла захвата"
        )
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    rec_hdr = struct.calcsize(endian + "IIII")
    while True:
        rec = fh.read(rec_hdr)
        if len(rec) < rec_hdr:
            if rec:
                raise CaptureFormatError("файл захвата оборван в середине пакета")
            return
        _sec, _frac, incl_len, _orig = struct.unpack(endian + "IIII", rec)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            raise CaptureFormatError("файл захвата оборван в середине пакета")
        yield linktype, data


def _pcapng_options(block: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    off = 0
    while off + 4 <= len(block):
        code, length = struct.unpack_from(endian + "HH", block, off)
        off += 4
        if code == 0:
            return
        yield code, block[off : off + length]
        off += length + (-length % 4)


#: Byte-order magic stored at the start of every section header. The block type
#: of an SHB is ``0x0A0D0D0A``, which reads the same in both byte orders, so the
#: raw bytes are what identify it.
_SHB_BYTES = b"\x0a\x0d\x0d\x0a"
_SHB_MAGIC = 0x1A2B3C4D

#: Field offsets inside an EPB body: interface id, timestamp high/low, captured
#: length, original length, then the packet data. Captured length is what bounds
#: the frame -- reading the original length instead yields the bytes that follow
#: the packet (options, the trailing block length) as if they were radio data.
_EPB_CAP_OFF = 12
_EPB_DATA_OFF = 20

#: SPB has no captured-length field at all: only the original length, then the
#: packet data immediately. A reader that expects a captured length there takes
#: the packet's own first four bytes as its length.
_SPB_LEN_OFF = 0
_SPB_DATA_OFF = 4

#: Obsolete packet block: interface id and drop count (2+2), two timestamp words
#: (4+4), captured and original length (4+4), then the data.
_PB_LEN_OFF = 12
_PB_DATA_OFF = 20


def _read_pcapng(fh, size: int) -> Iterator[tuple[int, bytes]]:
    """Yield (linktype, frame_bytes) from a pcapng file.

    Byte order is decided per section, from the SHB magic, and it has to be
    decided *before* any length is read: the block length is itself byte-ordered,
    so a big-endian file read as little-endian yields a nonsense length, and the
    resulting ``read()`` swallows the rest of the file and reports an empty
    capture with no error at all. Each block records its own interface, so the
    link type comes from that interface's IDB rather than from whichever IDB was
    seen last.
    """
    endian = "<"
    # Indexed by interface id: the nth IDB in a section describes interface n.
    linktypes: list[int] = []

    def link_for(interface: int) -> int:
        return linktypes[interface] if 0 <= interface < len(linktypes) else LINKTYPE_ETHERNET

    while True:
        head = fh.read(8)
        if len(head) < 8:
            if head:
                raise CaptureFormatError("файл pcapng оборван в середине блока")
            return

        if head[:4] == _SHB_BYTES:
            # Section header: the byte-order magic comes first in the body, so
            # read it before the length that is stored in that same byte order.
            magic_raw = fh.read(4)
            if len(magic_raw) < 4:
                raise CaptureFormatError("файл pcapng оборван в заголовке секции")
            if struct.unpack("<I", magic_raw)[0] == _SHB_MAGIC:
                endian = "<"
            elif struct.unpack(">I", magic_raw)[0] == _SHB_MAGIC:
                endian = ">"
            else:
                raise CaptureFormatError("неизвестный порядок байт в pcapng")
            total = struct.unpack(endian + "I", head[4:8])[0]
            # Smallest legal SHB: type+length+magic+version+section length+
            # trailing length = 4+4+4+4+8+4.
            if total < 28:
                raise CaptureFormatError("повреждённый pcapng блок")
            # The block occupies `total` bytes: 8 header + body + 4 trailing
            # length. 12 of those are the header and the trailing length, and 4
            # more (the magic) were just read, so this finishes the block.
            rest = fh.read(total - 12)
            if len(rest) < total - 12:
                raise CaptureFormatError("файл pcapng оборван в заголовке секции")
            # A new section starts with its own interface numbering.
            linktypes = []
            continue

        btype = struct.unpack(endian + "I", head[:4])[0]
        total = struct.unpack(endian + "I", head[4:8])[0]
        if total < 12:
            raise CaptureFormatError("повреждённый pcapng блок")
        body = fh.read(total - 8)
        if len(body) < total - 8:
            raise CaptureFormatError("файл pcapng оборван в середине блока")

        if btype == _PCAPNG_IDB:
            linktypes.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif btype == _PCAPNG_EPB:
            interface = struct.unpack_from(endian + "I", body, 0)[0]
            if len(body) < _EPB_DATA_OFF:
                raise CaptureFormatError("повреждённый pcapng блок с пакетом")
            cap_len = struct.unpack_from(endian + "I", body, _EPB_CAP_OFF)[0]
            yield link_for(interface), body[_EPB_DATA_OFF : _EPB_DATA_OFF + cap_len]
        elif btype == _PCAPNG_SPB:
            if len(body) < _SPB_DATA_OFF:
                raise CaptureFormatError("повреждённый pcapng блок с пакетом")
            orig_len = struct.unpack_from(endian + "I", body, _SPB_LEN_OFF)[0]
            # An SPB carries no interface id; it belongs to the section's first.
            yield link_for(0), body[_SPB_DATA_OFF : _SPB_DATA_OFF + orig_len]
        elif btype == _PCAPNG_PB:
            if len(body) < _PB_DATA_OFF:
                raise CaptureFormatError("повреждённый pcapng блок с пакетом")
            interface = struct.unpack_from(endian + "H", body, 0)[0]
            cap_len = struct.unpack_from(endian + "I", body, _PB_LEN_OFF)[0]
            yield link_for(interface), body[_PB_DATA_OFF : _PB_DATA_OFF + cap_len]


def iter_frames(path: str | Path) -> Iterator[tuple[int, bytes]]:
    """Yield (linktype, raw frame) pairs from a pcap or pcapng capture.

    Raises :class:`CaptureFormatError` when the file cannot be read as a
    capture at all, so that a broken file is never mistaken for an empty one.
    The file name is added here because the readers below have no other handle
    on it, and every message the user sees quotes the name they chose.
    """
    path = Path(path)
    with path.open("rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        try:
            if magic == b"\x0a\x0d\x0d\x0a":
                yield from _read_pcapng(fh, path.stat().st_size)
            else:
                yield from _read_pcap(fh, path.stat().st_size)
        except CaptureFormatError as exc:
            raise CaptureFormatError(f"{path.name}: {exc}") from None


# ---------------------------------------------------------------------------
# radiotap
# ---------------------------------------------------------------------------

# (bit, alignment, size) in the order the present-word declares them.
_RADIOTAP_FIELDS = {
    0: (8, 8),    # TSFT
    1: (1, 1),    # Flags
    2: (1, 1),    # Rate
    3: (2, 2),    # Channel
    4: (2, 2),    # FHSS
    5: (1, 1),    # dBm antenna signal
    6: (1, 1),    # dBm antenna noise
    7: (2, 2),    # Lock quality
    8: (4, 8),    # TSFT offset
    9: (2, 2),    # HE
    10: (2, 4),   # HE-MU
    11: (1, 1),   # reserved
    12: (1, 1),   # PSDU
    13: (4, 8),   # A-MPDU status
    14: (4, 8),   # A-MPDU status + MPDU count (special)
    15: (2, 2),   # HE-MU other user
    16: (2, 2),   # HE-MU other user
    17: (1, 1),   # reserved
    18: (0, 0),   # radiotap namespace (variable)
    19: (0, 0),   # vendor namespace (variable)
}


def strip_radiotap(data: bytes) -> bytes:
    """Return the 802.11 frame that follows a radiotap header."""
    if len(data) < 8:
        return data
    version = data[0]
    if version != 0:
        return data
    _pad, length = struct.unpack_from("<BB", data, 0)[1], struct.unpack_from("<H", data, 2)[0]
    if length < 8 or length > len(data):
        return data
    present = struct.unpack_from("<I", data, 4)[0]
    # extended present words
    words = [present]
    off = 8
    while present & 0x80000000:
        if off + 4 > length:
            break
        present = struct.unpack_from("<I", data, off)[0]
        words.append(present)
        off += 4

    pos = len(words) * 4 + 8
    for w_index, word in enumerate(words):
        for bit in range(0, 20):
            if not word & (1 << bit):
                continue
            if bit == 18:
                if w_index == 0 or word != words[w_index - 1]:
                    continue
                break
            if bit == 19:
                ns = struct.unpack_from("<HH", data, min(pos, length - 4))[0]
                pos += 4
                pos += -pos % ns if ns else 0
                sub = struct.unpack_from("<I", data, min(pos, length - 4))[0]
                size_map = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8}
                pos += 4
                align, size = size_map.get(sub, 4), size_map.get(sub, 4)
                pos += -pos % align if align else 0
                pos += size
                break
            align, size = _RADIOTAP_FIELDS.get(bit, (1, 1))
            pos += -pos % align if align else 0
            if bit == 14:
                pos += size + 4  # status + reserved + MPDU count
            else:
                pos += size
        if pos >= length:
            break
    return data[length:]


# ---------------------------------------------------------------------------
# 802.11 / EAPOL parsing
# ---------------------------------------------------------------------------

_EAPOL_KEY = 3
_BSSID_ADDR = bytes((0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
# LLC/SNAP header for IEEE 802.1X / EAPOL. The ethertype is 0x888E (big endian
# on the wire), i.e. the bytes 88 8E -- not 08 8E.
_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

#: An EAPOL-Key frame as it lies inside a data frame: the LLC/SNAP header above
#: followed by the EAPOL header's fixed part -- version 1, type 3 (Key). The
#: body length that comes after it is deliberately not part of this: it varies
#: per message, and pinning it would make the signature miss every real one.
#: These ten bytes occur in a capture only when a handshake is on the air, which
#: is what makes them worth searching for: one substring lookup over the bytes a
#: capture tool has just appended tells the capture loop that something
#: happened, without decoding a frame.
EAPOL_KEY_SIGNATURE = _SNAP_EAPOL + b"\x01\x03"

#: Chunk size for the signature search. The file is still being written while it
#: is read, so the search is incremental rather than whole-file.
_SCAN_CHUNK = 1 << 20


def first_key_frame(path: str | Path, start: int = 0) -> int | None:
    """Offset of the first EAPOL-Key frame at or after ``start``, else ``None``.

    Searches for :data:`EAPOL_KEY_SIGNATURE` instead of parsing frames. A minute
    of monitor-mode traffic is tens of megabytes of radiotap headers and
    encrypted payloads, and this is meant to be called every couple of seconds
    on a file that is still growing -- parsing all of it each time would cost
    more than the rest of the capture loop put together. ``start`` is where the
    previous call stopped, so each call looks only at what has been written
    since, and ``None`` then means "nothing new", not "nothing at all".

    Returns the offset rather than a bool because the caller uses it to resume
    from *after* the frame it has already judged.
    """
    overlap = len(EAPOL_KEY_SIGNATURE) - 1
    try:
        with Path(path).open("rb") as fh:
            fh.seek(max(0, start))
            pos = fh.tell()
            carry = b""
            while True:
                chunk = fh.read(_SCAN_CHUNK)
                window = carry + chunk
                found = window.find(EAPOL_KEY_SIGNATURE)
                if found >= 0:
                    return pos - len(carry) + found
                if not chunk:
                    return None
                pos += len(chunk)
                carry = window[-overlap:] if overlap else b""
    except OSError:
        # A file that cannot be read yet (still being created, or locked by the
        # capture tool) is simply one with nothing to report.
        return None


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass
class EapolKey:
    """One EAPOL-Key message extracted from a data frame."""

    src: bytes
    dst: bytes
    bssid: bytes
    replay: bytes
    descriptor_type: int
    key_info: int
    nonce: bytes
    mic: bytes
    key_data: bytes
    raw_eapol: bytes  # EAPOL-Key body with the MIC field zeroed

    @property
    def is_message1(self) -> bool:
        # 0x0080 = encrypted key data, 0x0100 = MIC present
        return bool(self.key_info & 0x0080) and not bool(self.key_info & 0x0100)

    @property
    def is_message2(self) -> bool:
        return bool(self.key_info & 0x0100) and not bool(self.key_info & 0x0080)

    @property
    def is_message3(self) -> bool:
        return bool(self.key_info & 0x0100) and bool(self.key_info & 0x0080)

    @property
    def is_message4(self) -> bool:
        return not bool(self.key_info & 0x0100) and not bool(self.key_info & 0x0080)

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & 0x0100)


def _extract_snap_payload(payload: bytes) -> bytes | None:
    """Return the EAPOL payload of a data frame, or None if not EAPOL."""
    if payload.startswith(_SNAP_EAPOL):
        return payload[8:]
    return None


def _parse_ie_chain(frame: bytes, off: int) -> dict[int, bytes]:
    ies: dict[int, bytes] = {}
    n = len(frame)
    while off + 2 <= n:
        ie_id = frame[off]
        ie_len = frame[off + 1]
        ies.setdefault(ie_id, frame[off + 2 : off + 2 + ie_len])
        off += 2 + ie_len
    return ies


def _rfc3394_pmkid_count(rsn_ie: bytes) -> int:
    """Return the PMKID list count (kde field 11) from an RSN IE."""
    if len(rsn_ie) < 10 or rsn_ie[0] != 48:
        return 0
    off = 2  # id + len
    off += 2  # version
    off += 4  # group cipher suite
    if off + 2 > len(rsn_ie):
        return 0
    pairwise_count = struct.unpack_from("<H", rsn_ie, off)[0]
    off += 2 + 4 * pairwise_count
    if off + 2 > len(rsn_ie):
        return 0
    akm_count = struct.unpack_from("<H", rsn_ie, off)[0]
    off += 2 + 4 * akm_count
    off += 2  # RSN capabilities
    if off + 2 > len(rsn_ie):
        return 0
    return struct.unpack_from("<H", rsn_ie, off)[0]


def _pmkids(rsn_ie: bytes) -> List[bytes]:
    count = _rfc3394_pmkid_count(rsn_ie)
    if count <= 0:
        return []
    off = 2 + 2 + 4
    pairwise_count = struct.unpack_from("<H", rsn_ie, off)[0]
    off += 2 + 4 * pairwise_count
    akm_count = struct.unpack_from("<H", rsn_ie, off)[0]
    off += 2 + 4 * akm_count + 2 + 2
    out = []
    for i in range(min(count, 16)):
        start = off + 16 * i
        if start + 16 > len(rsn_ie):
            break
        out.append(rsn_ie[start : start + 16])
    return out


# EAPOL-Key descriptor (key descriptor types 2/3) as it appears on the wire.
# Offsets verified byte-for-byte against a real capture cross-checked with
# wpawolf: the nonce starts at 13 and the MIC at 77, with the key data length
# at 93 and the key data at 95 (fixed part = 95 bytes).
#   0 descriptor type (1) | 1 key info (2) | 3 key length (2)
#   5 replay counter (8) | 13 nonce (32) | 45 IV (16) | 61 reserved (16)
#   77 MIC (16) | 93 key data length (2) | 95 key data
_EAPOL_KEY_MIN = 95
_OFF_NONCE = 13
_OFF_MIC = 77
_OFF_KEYDATA_LEN = 93
_OFF_KEYDATA = 95


def _parse_eapol_key(frame: bytes) -> tuple[int, int, bytes, bytes, bytes, bytes] | None:
    """Parse an EAPOL-Key message.

    ``frame`` is the whole EAPOL frame (4-byte header plus descriptor body).
    Returns ``(desc_type, key_info, replay, nonce, mic, key_data, raw)`` where
    ``raw`` is the frame with the MIC field zeroed -- that is exactly what
    hc22000 stores and what hashcat re-hashes to check a candidate password.
    """
    if len(frame) < 4 + _EAPOL_KEY_MIN:
        return None
    body = frame[4:]
    desc_type = body[0]
    key_info = struct.unpack_from(">H", body, 1)[0]
    replay = body[5:13]
    nonce = body[_OFF_NONCE : _OFF_NONCE + 32]
    mic = body[_OFF_MIC : _OFF_MIC + 16]
    key_data_len = struct.unpack_from(">H", body, _OFF_KEYDATA_LEN)[0]
    key_data = body[_OFF_KEYDATA : _OFF_KEYDATA + key_data_len]
    raw = bytearray(frame)
    raw[4 + _OFF_MIC : 4 + _OFF_MIC + 16] = b"\x00" * 16
    return desc_type, key_info, replay, nonce, mic, key_data, bytes(raw)


def _to_hex(raw: bytes) -> str:
    return raw.hex()


# ---------------------------------------------------------------------------
# candidate verification
# ---------------------------------------------------------------------------


def _prf512(password: bytes, label: bytes, data: bytes) -> bytes:
    """The IEEE 802.11i pseudo-random function, SHA-1 variant.

    ``P_hash`` over ``label || counter || data`` for as many HMACs as are asked
    for. This is the derivation both the PTK and, from it, the key-confirmation
    cipher come out of; anything that checks a WPA password checks it here.
    """
    out = b""
    counter = b"\x00\x00\x00\x01"
    while len(out) < 64:
        out += hmac.new(password, label + counter + data, hashlib.sha1).digest()
        counter = counter[:-1] + bytes([counter[-1] + 1])
    return out[:64]


@dataclass
class MicCheck:
    """One EAPOL message a candidate password can be checked against.

    Everything the check needs, and nothing about the password: a candidate is
    run through both derivations and the result compared with the MIC the frame
    already carries. A match is proof; a mismatch is proof too, which is what
    makes a stale stored key detectable instead of merely unhelpful.
    """

    bssid: bytes
    sta: bytes
    anonce: bytes
    snonce: bytes
    mic: bytes
    eapol: bytes  # the frame with its MIC field zeroed
    #: The network's name, as bytes. WPA-PSK is a two-step derivation and the
    #: name belongs in the first step: PMK = PBKDF2(passphrase, ESSID), and only
    #: then does the PTK come out of the addresses and the nonces. Skipping it
    #: makes every comparison fail, including the right password's.
    essid: bytes = b""


def verify_password(password: str, check: MicCheck) -> bool:
    """Whether ``password`` is the one that produced this frame's MIC.

    The chain is the one hashcat mode 22000 implements: the passphrase and the
    network name give the PMK, the PMK with the two addresses and the two nonces
    gives the PTK, and the first sixteen bytes of the PTK sign the frame as
    HMAC-MD5. Anything shorter matches nothing, which is worth knowing: a check
    that cannot pass is a silent guarantee that is easy to mistake for a
    negative result.
    """
    try:
        pwd = password.encode("utf-8")
    except UnicodeEncodeError:
        return False
    ptk = derive_ptk(pwd, check)
    if ptk is None:
        return False
    computed = hmac.new(ptk[:16], check.eapol, hashlib.md5).digest()
    return hmac.compare_digest(computed, check.mic)


def derive_ptk(passphrase: bytes, check: MicCheck) -> bytes | None:
    """The 48-byte PTK for ``check``, or None when there is nothing to derive from."""
    if not check.anonce or not check.snonce or not check.bssid or not check.sta:
        return None
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase, check.essid, 4096, 32)
    a, s = sorted((check.bssid, check.sta))
    first, second = sorted((check.anonce, check.snonce))
    return _prf512(pmk, b"Pairwise key expansion", a + s + first + second)[:48]


def _hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


# ---------------------------------------------------------------------------
# conversion
# ---------------------------------------------------------------------------


@dataclass
class ConversionReport:
    pmkid: List[str] = field(default_factory=list)
    eapol: List[str] = field(default_factory=list)
    essids: int = 0
    frames: int = 0
    #: True when an external converter (wpawolf) produced these records, so the
    #: frame counters below were never filled: that program read the capture, not
    #: this module. Without it the "no hashes" summary would claim a capture
    #: wpawolf had already parsed held no 802.11 traffic at all.
    external: bool = False
    #: Frames recognised as 802.11 -- any frame type, not just EAPOL. Counted
    #: separately because "the capture is empty" and "the capture is not
    #: 802.11 at all" are different problems with different fixes.
    dot11_frames: int = 0
    #: Data frames carrying an EAPOL-Key message. This is the number that says
    #: whether a handshake was on the air, so it has to count only real EAPOL
    #: frames: counting every 802.11 frame here reported dozens of "EAPOL
    #: frames" for a capture containing two handshake messages, which is the
    #: figure the user is told when a capture came up empty.
    eapol_frames: int = 0
    #: True when the file stopped mid-block after some frames had already been
    #: read. That is what a capture tool killed mid-write leaves behind, and it
    #: is worth saying out loud: the hashes recovered so far are valid, but the
    #: file is cut short, so a miss here is a shorter capture than it looks.
    truncated: bool = False
    #: Why the file was cut short, for the same reason.
    detail: str = ""
    #: Messages a candidate password can be checked against, gathered while the
    #: records are built. Empty for an external converter, which reads the file
    #: itself and reports none -- so a verification that finds nothing here is
    #: "cannot check", not "wrong password".
    checks: List[MicCheck] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.pmkid) + len(self.eapol)

    @property
    def ok(self) -> bool:
        return bool(self.pmkid or self.eapol)


def _handle_frame(
    linktype: int,
    data: bytes,
    essids: dict[str, str],
    keys: list[EapolKey],
) -> str:
    """Parse one frame; returns what it turned out to be.

    ``"802.11"`` for a frame recognised as 802.11 but carrying no EAPOL-Key,
    ``"eapol"`` for one that does. The distinction is what the conversion report
    shows the user when nothing was recovered.
    """
    if linktype == LINKTYPE_IEEE802_11_RADIOTAP:
        frame = strip_radiotap(data)
    elif linktype in (LINKTYPE_IEEE802_11, LINKTYPE_RAW, LINKTYPE_ETHERNET):
        frame = data[14:] if linktype == LINKTYPE_ETHERNET else data
    else:
        return "other"
    if len(frame) < 24:
        return "other"

    # IEEE 802.11 Frame Control, transmitted LSB-first within each byte:
    #   byte0: bits 0-1 protocol version, bits 2-3 type, bits 4-7 subtype
    #   byte1: bit 0 To DS, bit 1 From DS, bit 4 Protected, bit 5 Order/+HTC
    fc0, fc1 = frame[0], frame[1]
    ftype = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F
    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    has_htc = bool(fc1 & 0x20)

    if ftype == 0 and subtype in (0x05, 0x08, 0x00, 0x01):
        # management frames carry the SSID -> learn the BSSID -> SSID mapping
        if subtype in (0x08, 0x05):  # beacon / probe response: addr1 = BSSID
            bssid, ie_off = frame[4:10], 24 + 12
        elif subtype == 0x01:  # association response: addr1 = BSSID
            bssid, ie_off = frame[4:10], 24 + 6
        else:  # association request: addr3 = BSSID
            bssid, ie_off = frame[16:22], 24 + 4
        if bssid and bssid != _BSSID_ADDR:
            ssid_ie = _parse_ie_chain(frame, ie_off).get(0)
            if ssid_ie and ssid_ie != b"\x00":
                essids.setdefault(mac_str(bssid), ssid_ie.decode("utf-8", "replace"))
        return "802.11"

    if ftype != 2:
        return "802.11"

    off = 24
    if to_ds and from_ds:
        off += 6  # Address 4
    if subtype & 0x08:  # QoS data: 2-byte QoS Control follows the sequence number
        off += 2
        if has_htc:
            off += 4  # HT Control

    payload = _extract_snap_payload(frame[off:])
    if payload is None or len(payload) < 4:
        return "802.11"
    if payload[1] != _EAPOL_KEY:
        return "802.11"

    parsed = _parse_eapol_key(payload)
    if parsed is None:
        return "802.11"
    desc_type, key_info, replay, nonce, mic, key_data, raw = parsed

    addr1, addr2, addr3 = frame[4:10], frame[10:16], frame[16:22]
    # Resolve the BSSID against the ESSID map learned from beacons, which is more
    # reliable than the DS direction bits: captures exist where addr1 of a
    # From-DS frame is not the BSSID. addr3 is preferred because it is the BSSID
    # in every standard To-DS frame.
    bssid = None
    for candidate in (addr3, addr2, addr1):
        if candidate and candidate != _BSSID_ADDR and mac_str(candidate) in essids:
            bssid = candidate
            break

    def station() -> bytes:
        """The client's address, from whichever slot the direction bits put it in.

        To-DS carries the station as the transmitter (addr2) and the AP as both
        addr1 and addr3; From-DS is the other way round, with the AP as addr2 and
        the client as addr1 and addr3. EAPOL M2 and M3 -- the two messages a
        record is built from -- arrive From-DS, so the station has to be taken
        from there.
        """
        first = addr2 if to_ds and not from_ds else addr1
        for candidate in (first, addr3, addr1, addr2):
            if candidate and candidate != _BSSID_ADDR:
                return candidate
        return addr2

    if bssid is None:
        if to_ds and not from_ds:
            src, dst, bssid = station(), addr1, addr3
        elif from_ds and not to_ds:
            # The AP is the *transmitter* here, addr2. addr1 is the receiver,
            # i.e. the client, and taking it for the BSSID wrote the station's
            # own randomised address into the BSSID field of every record. That
            # one swapped pair is what made a capture holding ten good hashes
            # come out of the run as containing none -- every run filters the
            # records by the target network's BSSID, and none of them matched.
            src, dst, bssid = station(), addr2, addr2
        else:
            src, dst, bssid = station(), addr2, frame[24:30]
    else:
        dst = bssid
        src = next(
            (c for c in (addr1, addr2, addr3) if c != bssid and c != _BSSID_ADDR),
            addr2,
        )

    keys.append(
        EapolKey(
            src=src,
            dst=dst,
            bssid=bssid,
            replay=replay,
            descriptor_type=desc_type,
            key_info=key_info,
            nonce=nonce,
            mic=mic,
            key_data=key_data,
            raw_eapol=raw,
        )
    )
    return "eapol"


def _build_lines(
    keys: list[EapolKey], essids: dict[str, str], essid_hint: str = ""
) -> tuple[List[str], List[str], List[MicCheck]]:
    """Emit hc22000 records.

    Two details matter for the result to be crackable, and both are easy to get
    wrong -- they are matched here against wpawolf's output on real captures:

    * ``NONCE_AP`` must hold the AP nonce (ANonce), not the nonce carried by the
      exported message. hashcat re-derives the PTK from the ESSID, the two MACs
      and this nonce, so feeding it the SNonce produces a PTK that never
      verifies and the crack always fails.
    * ``MESSAGEPAIR`` is a hex code identifying which messages were combined,
      e.g. ``82`` = M2+M3 with the EAPOL body from M2, ``13`` = M2+M3 with the
      body from M3, ``80`` = M1+M2 challenge.

    Field encoding follows the reference byte for byte: MAC addresses and the
    ESSID are lower-case hex without separators, as are the nonce, MIC and EAPOL
    body.

    ``essid_hint`` is the network's own name, passed in because a short capture
    can easily hold the handshake and no beacon. Without a beacon the ESSID map
    is empty, the record gets a blank ESSID field, and hashcat cannot verify a
    single candidate against it -- the handshake is in hand and the crack still
    finds nothing. A known name from the scan list is better than a blank.
    """
    pmkid_lines: List[str] = []
    eapol_lines: List[str] = []
    checks: List[MicCheck] = []
    seen_pmkid: set[str] = set()
    seen_eapol: set[str] = set()

    def essid_hex(b: str) -> str:
        return b.encode("utf-8").hex()

    def name_for(bssid: bytes) -> str:
        return essids.get(mac_str(bssid)) or essid_hint

    m1s = [k for k in keys if k.is_message1]
    m2s = [k for k in keys if k.is_message2]
    m3s = [k for k in keys if k.is_message3]

    for key in m1s:
        # The key data of M1 is the AP's RSN IE; a vulnerable AP also appends
        # its PMKID list to it.
        for pmkid in _pmkids(key.key_data):
            line = (
                f"WPA*01*{_to_hex(pmkid)}*{key.bssid.hex()}*"
                f"{key.src.hex()}*{essid_hex(name_for(key.bssid))}***1"
            )
            if line not in seen_pmkid:
                seen_pmkid.add(line)
                pmkid_lines.append(line)

    def emit(second: EapolKey, nonce_ap: bytes, pair: str) -> None:
        # Only pairs whose nonce field really is the AP nonce can be verified
        # here: the record's NONCE_AP is the AP's, but a check also needs the
        # station's, which no hc22000 field carries. The 82 and 80 codes are
        # exactly the ones built from a message whose own nonce is the SNonce
        # with the AP nonce taken from its partner.
        if pair in ("82", "80") and any(second.nonce):
            checks.append(MicCheck(
                bssid=second.bssid, sta=second.src,
                anonce=nonce_ap[:32], snonce=second.nonce,
                mic=second.mic, eapol=second.raw_eapol,
                essid=name_for(second.bssid).encode("utf-8"),
            ))
        line = (
            f"WPA*02*{_to_hex(second.mic)}*{second.bssid.hex()}*"
            f"{second.src.hex()}*{essid_hex(name_for(second.bssid))}*"
            f"{_to_hex(nonce_ap[:32])}*{_to_hex(second.raw_eapol)}*{pair}"
        )
        if line not in seen_eapol:
            seen_eapol.add(line)
            eapol_lines.append(line)

    def _rc(msg) -> Optional[int]:
        # EAPOL fields are big endian, including the replay counter.
        return int.from_bytes(msg.replay, "big") if len(msg.replay) == 8 else None

    positions = {id(key): index for index, key in enumerate(keys)}

    def nearest(message: EapolKey, candidates: list[EapolKey], *, after: bool = False):
        if not candidates:
            return None
        position = positions[id(message)]
        return min(candidates, key=lambda other: (
            (positions[id(other)] < position) if after else (positions[id(other)] > position),
            abs(positions[id(other)] - position),
        ))

    # AP, client and replay counter identify a handshake. The same AP can serve
    # several clients or successive sessions with different ANonces.
    paired_m3: dict[int, list[EapolKey]] = {}
    for m2 in m2s:
        if not m2.has_mic:
            continue
        rc2 = _rc(m2)
        if rc2 is None:
            continue
        m1 = nearest(m2, [m for m in m1s if m.bssid == m2.bssid and m.src == m2.src
                           and _rc(m) == rc2 and any(m.nonce)])
        partners = [m for m in m3s if m.bssid == m2.bssid and m.src == m2.src
                    and _rc(m) == rc2 + 1 and any(m.nonce)
                    and (m1 is None or m.nonce == m1.nonce)]
        m3 = nearest(m2, partners, after=True)
        if m3 is not None:
            emit(m2, m3.nonce, "82")
            for partner in partners:
                if partner.nonce == m3.nonce:
                    paired_m3.setdefault(id(partner), []).append(m2)
        elif m1 is not None:
            emit(m2, m1.nonce, "80")

    for m3 in m3s:
        if not m3.has_mic or not any(m3.nonce):
            continue
        candidates = paired_m3.get(id(m3), [])
        # Prefer a partner that actually carries the SNonce: retransmits of M2
        # can arrive with a zeroed nonce, and the 13 code needs the real one.
        partner = nearest(m3, [m for m in candidates if any(m.nonce)] or candidates)
        if partner is None:
            emit(m3, m3.nonce[:32], "11")  # M3+M4, ANonce from M3
        else:
            # AP-less variant: hashcat is handed the SNonce and told to apply
            # nonce-error corrections, matching the reference output.
            emit(m3, partner.nonce[:32], "13")

    return pmkid_lines, eapol_lines, checks


def convert(
    capture: str | Path,
    out_path: str | Path | None = None,
    bssid_filter: str | None = None,
    *,
    should_stop: Callable[[], bool] | None = None,
    essid_hint: str = "",
    essid_filter: str | None = None,
) -> ConversionReport:
    """Convert a pcap/pcapng capture to an hc22000 hash file.

    Raises :class:`CaptureFormatError` when the file holds no readable capture.
    A file that stops mid-block after frames have already been read is not an
    error -- those frames are real -- so conversion stops there and says so via
    ``report.truncated``.

    ``essid_filter`` widens what is accepted from one exact BSSID to any BSSID
    whose own beacon announced that name. The WPA key is derived from the SSID,
    so a handshake with a neighbouring access point of the *same* network -- the
    other band of the same router, a second AP of a mesh -- verifies the very
    same passwords, and filtering it out threw away a capture that had the
    handshake in it. Only a BSSID whose name was actually seen in the capture
    qualifies: a record with no name of its own was handed ``essid_hint`` and
    would otherwise match anything, including a neighbour's network.
    """
    report = ConversionReport()
    essids: dict[str, str] = {}
    keys: list[EapolKey] = []
    # Accept "aa:bb:cc:dd:ee:ff" or "aabbccddeeff"; records store bare hex.
    want = normalize_bssid(bssid_filter) if bssid_filter else None
    want_name = essid_filter or None

    try:
        for linktype, data in iter_frames(capture):
            if should_stop is not None and should_stop():
                raise InterruptedError("Конвертация отменена")
            report.frames += 1
            kind = _handle_frame(linktype, data, essids, keys)
            if kind == "eapol":
                report.eapol_frames += 1
            elif kind == "802.11":
                report.dot11_frames += 1
    except CaptureFormatError as exc:
        if report.frames == 0:
            # Nothing at all came out of the file, so there is no capture to
            # report on. Re-raised: this is a broken file, not a quiet one, and
            # the two must not reach the screen with the same wording.
            raise
        report.truncated = True
        report.detail = str(exc)

    report.essids = len(essids)
    pmkid_lines, eapol_lines, report.checks = _build_lines(keys, essids, essid_hint)
    if should_stop is not None and should_stop():
        raise InterruptedError("Конвертация отменена")

    if want or want_name:
        # The access points that announced this network's name, heard in this
        # capture. Anything else belongs to someone else. The map is keyed by a
        # colon-separated MAC while records carry bare hex, so it is normalised
        # here -- comparing them as they are matches nothing at all.
        family = {b.replace(":", "").lower() for b, name in essids.items()
                  if want_name and name == want_name}
        keep = [lambda ln: _field(ln, 3) == want,
                lambda ln: _field(ln, 3) in family]
        pmkid_lines = [ln for ln in pmkid_lines if any(test(ln) for test in keep)]
        eapol_lines = [ln for ln in eapol_lines if any(test(ln) for test in keep)]

    report.pmkid = pmkid_lines
    report.eapol = eapol_lines

    if out_path is not None and (pmkid_lines or eapol_lines):
        Path(out_path).write_text(
            "\n".join(pmkid_lines + eapol_lines) + "\n", encoding="utf-8"
        )
    return report


def _field(line: str, index: int) -> str:
    """One ``*``-separated field of an hc22000 record."""
    parts = line.split("*")
    return parts[index] if len(parts) > index else ""


def summarise(report: ConversionReport) -> str:
    if not report.ok:
        if report.external:
            return "Хэши не найдены: конвертер не извлёк ни рукопожатий, ни PMKID"
        if report.truncated:
            return (
                f"Файл захвата оборван, прочитано {report.frames} кадров. "
                f"{report.detail}\nЗахват не был дописан до конца — возможно, "
                "инструмент захвата прервали, а не он завершился сам."
            )
        if not report.dot11_frames and not report.eapol_frames:
            return f"Хэши не найдены: в файле нет кадров 802.11 (кадров {report.frames})"
        return (
            f"Хэши не найдены: рукопожатий и PMKID нет "
            f"(кадров 802.11: {report.dot11_frames + report.eapol_frames}, "
            f"из них EAPOL: {report.eapol_frames})"
        )
    parts = []
    if report.pmkid:
        parts.append(f"PMKID x{len(report.pmkid)}")
    if report.eapol:
        parts.append(f"EAPOL x{len(report.eapol)}")
    text = ", ".join(parts)
    if report.truncated:
        text += f" (файл оборван на {report.frames} кадрах)"
    return text
