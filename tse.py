#!/usr/bin/env python3
"""
Parse TSE/DSFinV-K V0 QR code and verify signature.
Signed payload = ASN.1 DER structure per Java reference:
  https://github.com/berohndo/tse_signature_verification (createRawDataFromQrCode)
"""

import sys
import json
import base64
import re
from datetime import datetime, timedelta, timezone
import argparse
from decimal import Decimal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
from asn1crypto.core import Integer, ObjectIdentifier, OctetString, Sequence, UTCTime, GeneralizedTime

TAX_CLASS_LABELS = {
    0: "USt 19%",
    1: "USt 7%",
    2: "USt 0%",
    3: "USt Sonder",
    4: "USt Sonder2"
}

def parse_money(value):
    value = value.strip()
    if "," in value and "." in value:
        # selten, aber defensiv
        value = value.replace(".", "").replace(",", ".")
    else:
        value = value.replace(",", ".")
    return Decimal(value)

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)  # exakt erhalten
        return super().default(obj)

def parse_process_data(process_data):
    result = {"raw": process_data, "parsed": None}

    if "^" not in process_data:
        return result

    parts = process_data.split("^")
    if len(parts) != 3:
        return result

    process_name = parts[0]
    tax_block = parts[1]
    payment_block = parts[2]

    taxes_raw = tax_block.split("_")
    tax_entries = []
    for i, value in enumerate(taxes_raw):
        decimal_value = parse_money(value)
        if decimal_value != Decimal("0"):
            tax_entries.append({
                "class_index": i,
                "label": TAX_CLASS_LABELS.get(i, f"TaxClass{i+1}"),
                "decimal": decimal_value
            })

    payment_total_raw = None
    payment_type = None
    if ":" in payment_block:
        payment_total_raw, payment_type = payment_block.split(":", 1)

    result["parsed"] = {
        "process_name": process_name,
        "tax_values_raw": taxes_raw,
        "tax_values_parsed": tax_entries,
        "payment": {
            "total_raw": payment_total_raw,
            "total_float": parse_money(payment_total_raw) if payment_total_raw else None,
            "type": payment_type
        }
    }

    return result


# --- ASN.1 DER helpers (match Java createRawDataFromQrCode) ---

# Manual DER helpers removed: we now rely on asn1crypto for canonical DER encoding.


def _iso8601_to_unix_time(date_time_string: str, ignore_offset: bool = False) -> int:
    """Parse ISO-8601 date-time to Unix seconds.

    Accepts either an instant ending with 'Z' or an offset like '+01:00' or
    '+0100' (an optional space before the offset is tolerated). If
    `ignore_offset` is True the parsed wall-clock fields are treated as UTC
    (i.e. any written offset is ignored).
    """
    s = date_time_string.strip()
    # Single regex to match either Z or an offset (with optional space)
    # Groups: 1=Y 2=Mo 3=D 4=H 5=Min 6=S 7=frac (optional) 8=sign (None if Z) 9=off_h 10=off_m
    m = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z| ?([+-])(\d{2}):?(\d{2}))$",
        s,
    )
    if not m:
        raise ValueError(f"Invalid ISO-8601 date-time: {date_time_string}")
    y, mo, d, h, mi, s_ = (int(m.group(i)) for i in range(1, 7))
    sign = m.group(8)
    if sign is None or ignore_offset:
        # Either a Z-suffixed time, or we're instructed to ignore any offset
        dt = datetime(y, mo, d, h, mi, s_, tzinfo=timezone.utc)
        return int(dt.timestamp())
    off_h, off_m = int(m.group(9)), int(m.group(10))
    sign_mul = 1 if sign == '+' else -1
    tz = timezone(timedelta(seconds=sign_mul * (off_h * 3600 + off_m * 60)))
    dt = datetime(y, mo, d, h, mi, s_, tzinfo=tz)
    return int(dt.timestamp())


def _signature_algorithm_to_oid(sig_alg: str) -> str:
    try:
        return {
            "ecdsa-plain-sha256": "0.4.0.127.0.7.1.1.4.1.3",
            "ecdsa-plain-sha384": "0.4.0.127.0.7.1.1.4.1.4",
        }[sig_alg.strip().lower()]
    except KeyError:
        raise ValueError(f"Unsupported sig_alg: {sig_alg}")


def create_raw_data_from_qr_code(fields, public_key_decoded: bytes, use_tz: bool = True) -> bytes:
    """
    Build the exact ASN.1 DER signed payload per Java createRawDataFromQrCode.
    fields: 12 QR fields (index 0 = version, 1 = kassen_seriennummer, ... 11 = public_key_b64).
    time_offset_seconds: added to the parsed finish time (unixTime) to try TSE time interpretation.
    """
    if len(fields) != 12:
        raise ValueError("Expected 12 QR fields")
    version = 2
    certified_data_type = "0.4.0.127.0.7.3.7.1.1"
    operation_type = b"FinishTransaction"
    client_id = fields[1].encode("utf-8")
    process_type = fields[2].encode("utf-8")
    process_data = fields[3].encode("utf-8")
    transaction_number = fields[4]
    signature_counter = int(fields[5])
    date_time_string = fields[7]   # finish_zeit
    sig_alg = fields[8]
    log_time_format = fields[9]
    # serialNumber = SHA256(decoded public key)
    h = hashes.Hash(hashes.SHA256())
    h.update(public_key_decoded)
    serial_number = h.finalize()

    # Java order (BouncyCastle uses IMPLICIT tagging: 0x80+tag, length, raw content)

    ver_tlv = Integer(version).dump()
    oid_tlv = ObjectIdentifier(certified_data_type).dump()

    # context-specific IMPLICIT tags: use retag({'implicit': N}) on OctetString
    el_op = OctetString(operation_type).retag({'implicit': 0}).dump()
    el_client = OctetString(client_id).retag({'implicit': 1}).dump()
    el_proc_data = OctetString(process_data).retag({'implicit': 2}).dump()
    el_proc_type = OctetString(process_type).retag({'implicit': 3}).dump()

    trans_bytes = _int_to_minimal_bytes(int(transaction_number))
    el_trans = OctetString(trans_bytes).retag({'implicit': 5}).dump()

    serial_tlv = OctetString(serial_number).dump()

    sigalg_oid = ObjectIdentifier(_signature_algorithm_to_oid(sig_alg)).dump()
    sigalg_seq = Sequence()
    sigalg_seq.contents = sigalg_oid
    sigalg_seq_tlv = sigalg_seq.dump()

    sigcount_tlv = Integer(signature_counter).dump()

    elements = [
        ver_tlv,
        oid_tlv,
        el_op,
        el_client,
        el_proc_data,
        el_proc_type,
        el_trans,
        serial_tlv,
        sigalg_seq_tlv,
        sigcount_tlv,
    ]

    if log_time_format == "unixTime":
        # use_tz=True: honor timezone offsets from the QR (standard-compliant)
        # use_tz=False: ignore offsets and treat wall-clock as UTC (compat mode)
        unix_ts = _iso8601_to_unix_time(date_time_string, ignore_offset=(not use_tz))
        elements.append(Integer(unix_ts).dump())
    elif log_time_format == "utcTime":
        unix = _iso8601_to_unix_time(date_time_string)
        dt = datetime.fromtimestamp(unix, tz=timezone.utc)
        elements.append(UTCTime(dt).dump())
    elif log_time_format == "generalizedTime":
        unix = _iso8601_to_unix_time(date_time_string)
        dt = datetime.fromtimestamp(unix, tz=timezone.utc)
        elements.append(GeneralizedTime(dt).dump())
    else:
        raise ValueError(f"Unhandled logTimeFormat: {log_time_format}")

    return b"".join(elements)


def _int_to_minimal_bytes(i: int) -> bytes:
    """Minimal unsigned big-endian bytes (Java BigInteger.toByteArray() for positive)."""
    if i < 0:
        raise ValueError("Expected non-negative transaction number")
    if i == 0:
        return b"\x00"
    b = i.to_bytes((i.bit_length() + 8) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


# _der_utc_time and _der_generalized_time removed — use asn1crypto UTCTime/GeneralizedTime


def verify_signature(payload_bytes, signature_bytes, public_key_bytes, sig_alg):
    """
    Verify TSE/DSFinV-K ECDSA signature over the signed payload.

    Public key: either raw 65-byte uncompressed EC point (04||x||y) for P-256,
                or DER-encoded SubjectPublicKeyInfo (SPKI).
    Signature:  either raw 64-byte r||s (32+32) or DER-encoded ECDSA signature.
                We build ASN.1/DER from r,s like the Java reference (SEQUENCE of two INTEGERs).
    """
    sig_alg_lower = sig_alg.strip().lower()
    if sig_alg_lower == "ecdsa-plain-sha256":
        hash_alg = hashes.SHA256()
        curve = ec.SECP256R1()
    elif sig_alg_lower == "ecdsa-plain-sha384":
        hash_alg = hashes.SHA384()
        curve = ec.BrainpoolP384R1()
    else:
        raise ValueError(f"Unsupported sig_alg: {sig_alg}")

    # --- Public key: attempt raw uncompressed point first, then fallback to DER/SPKI ---
    public_key = None
    if len(public_key_bytes) > 0 and public_key_bytes[0] == 0x04:
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)
        except Exception:
            public_key = None

    if public_key is None:
        try:
            public_key = load_der_public_key(public_key_bytes)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("DER public key is not an EC key")
        except Exception as e:
            raise ValueError(f"Failed to parse public key bytes: {e}") from e

    # --- Signature: raw r||s (coord_len*2) or DER ---
    coord_len = (curve.key_size + 7) // 8
    if len(signature_bytes) == 2 * coord_len:
        r = int.from_bytes(signature_bytes[:coord_len], byteorder="big")
        s = int.from_bytes(signature_bytes[coord_len:], byteorder="big")
        signature_der = utils.encode_dss_signature(r, s)
    else:
        signature_der = signature_bytes

    try:
        public_key.verify(signature_der, payload_bytes, ec.ECDSA(hash_alg))
        return True
    except InvalidSignature:
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify TSE/DSFinV-K V0 QR signature")
    parser.add_argument("--use-tz", choices=["0", "1"], default="0",
                        help="1=honor timezone offsets (standard). 0=ignore offsets (compat). Default 0")
    args = parser.parse_args()
    use_tz = args.use_tz == "1"

    raw = sys.stdin.read().strip()
    if not raw:
        sys.exit("No input received")

    fields = raw.split(";")
    if len(fields) != 12:
        sys.exit(f"Unexpected field count: {len(fields)} (expected 12)")

    # DSFinV-K V0 Felder
    qr_code_version     = fields[0]
    kassen_seriennummer = fields[1]
    process_type        = fields[2]
    process_data        = fields[3]
    transaktionsnummer  = fields[4]
    signatur_zaehler    = fields[5]
    start_zeit          = fields[6]
    finish_zeit         = fields[7]
    sig_alg             = fields[8]
    log_time_format     = fields[9]
    signatur_b64        = fields[10]
    public_key_b64      = fields[11]

    # Base64 dekodieren (public key wird für Signed-Payload benötigt: serialNumber = SHA256(pk))
    signature_bytes = base64.b64decode(signatur_b64)
    public_key_bytes = base64.b64decode(public_key_b64)

    # Detect public key format and basic validity (point on expected curve)
    public_key_info = {
        "base64": public_key_b64,
        "decoded_length": len(public_key_bytes),
        "format": None,
        "valid_on_curve": None,
        "validity_error": None,
    }
    try:
        if len(public_key_bytes) > 0 and public_key_bytes[0] == 0x04:
            public_key_info["format"] = "uncompressed_point"
            # pick curve from sig_alg for validation (best-effort)
            try:
                sig_alg_lower = sig_alg.strip().lower()
                if sig_alg_lower == "ecdsa-plain-sha256":
                    chk_curve = ec.SECP256R1()
                elif sig_alg_lower == "ecdsa-plain-sha384":
                    chk_curve = ec.BrainpoolP384R1()
                else:
                    chk_curve = None
                if chk_curve is not None:
                    xlen = (chk_curve.key_size + 7) // 8
                    x = int.from_bytes(public_key_bytes[1:1 + xlen], "big")
                    y = int.from_bytes(public_key_bytes[1 + xlen:1 + 2 * xlen], "big")
                    nums = ec.EllipticCurvePublicNumbers(x, y, chk_curve)
                    # this may raise if point not on curve
                    nums.public_key()
                    public_key_info["valid_on_curve"] = True
            except Exception as e:
                public_key_info["valid_on_curve"] = False
                public_key_info["validity_error"] = str(e)
        else:
            # not an uncompressed point — mark as DER/SPKI or unknown
            public_key_info["format"] = "der_or_spki"
    except Exception as e:
        public_key_info["validity_error"] = str(e)

    # Build payload and verify (no time-offset trials)
    payload_bytes = create_raw_data_from_qr_code(fields, public_key_bytes, use_tz=use_tz)
    try:
        verified = verify_signature(payload_bytes, signature_bytes, public_key_bytes, sig_alg)
        verification_error = None
    except Exception as e:
        verified = False
        verification_error = str(e)

    output = {
        "raw_line": raw,
        "qr_fields": {
            "qr_code_version": qr_code_version,
            "kassen_seriennummer": kassen_seriennummer,
            "process_type": process_type,
            "process_data": parse_process_data(process_data),
            "transaktionsnummer": transaktionsnummer,
            "signatur_zaehler": signatur_zaehler,
            "start_zeit": start_zeit,
            "finish_zeit": finish_zeit,
            "sig_alg": sig_alg,
            "log_time_format": log_time_format,
            "signatur": {
                "base64": signatur_b64,
                "decoded_length": len(signature_bytes)
            },
            "public_key": public_key_info
        },
        "signed_payload_der_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "signed_payload_der_length": len(payload_bytes),
        "use_tz": use_tz,
        "signature_verified": verified,
        "verification_error": verification_error,
        
    }

    print(json.dumps(output, indent=2, ensure_ascii=False, cls=DecimalEncoder))

if __name__ == "__main__":
    main()

