"""Protocol-level constants for MTProto, TLS and WebSocket layers."""

ZERO_64 = b"\x00" * 64

# --- MTProto obfuscation handshake ---------------------------------------

HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"

PROTO_INT_ABRIDGED = 0xEFEFEFEF
PROTO_INT_INTERMEDIATE = 0xEEEEEEEE
PROTO_INT_PADDED_INTERMEDIATE = 0xDDDDDDDD

# Bytes/patterns that must NOT appear at the start of a relay handshake,
# because Telegram protocol detection uses them as markers for HTTP, TLS etc.
RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {
    b"\x48\x45\x41\x44",  # "HEAD"
    b"\x50\x4f\x53\x54",  # "POST"
    b"\x47\x45\x54\x20",  # "GET "
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",  # TLS record header
}
RESERVED_CONTINUE = b"\x00\x00\x00\x00"

# Default IPs (used as final TCP fallback when WS is unreachable).
DC_DEFAULT_IPS = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}

# Valid DC numbers we route to.
DC_IDS = (1, 2, 3, 4, 5, 203)

# --- TLS record types ----------------------------------------------------

TLS_RECORD_CCS = 0x14
TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_APPDATA = 0x17

TLS_APPDATA_MAX = 16384

# --- Fake TLS handshake layout ------------------------------------------

CLIENT_RANDOM_OFFSET = 11
CLIENT_RANDOM_LEN = 32
SESSION_ID_OFFSET = 44
SESSION_ID_LEN = 32

# Tolerance for client_random embedded timestamp (seconds).
TIMESTAMP_TOLERANCE = 120

# --- WebSocket -----------------------------------------------------------

WS_OP_CONT = 0x0
WS_OP_TEXT = 0x1
WS_OP_BINARY = 0x2
WS_OP_CLOSE = 0x8
WS_OP_PING = 0x9
WS_OP_PONG = 0xA

WS_FIN_BIT = 0x80
WS_MASK_BIT = 0x80
