import struct
import tempfile

from agentic_binary_analysis.analysis.binary_static import (
    extract_crypto_constants,
    extract_strings_with_context,
)


def test_extract_crypto_constants_md5():
    data = b"AAAA" + b"".join(struct.pack("<I", w) for w in [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(data)
        path = handle.name

    result = extract_crypto_constants(path)
    assert any(m["name"] == "md5_init" for m in result["matches"])


def test_extract_strings_with_context():
    data = b"\x00\x00hello_world\x00\x00"
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(data)
        path = handle.name

    result = extract_strings_with_context(path, min_length=5)
    values = [s["value"] for s in result["strings"]]
    assert "hello_world" in values
