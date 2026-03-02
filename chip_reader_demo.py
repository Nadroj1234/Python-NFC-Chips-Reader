from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.Exceptions import CardConnectionException, NoCardException
import time
import string
import json

# =========================
# SMART CARD STATUS CODES
# =========================

STATUS_SUCCESS_SW1 = 0x90
STATUS_SUCCESS_SW2 = 0x00

ERROR_CARD_UNRESPONSIVE_HEX = "80100066"  # SCARD_W_UNRESPONSIVE_CARD
ERROR_CARD_REMOVED_HEX = "80100069"       # SCARD_W_REMOVED_CARD


# =========================
# PC/SC APDU COMMANDS
# =========================

APDU_GET_CARD_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]


def is_transient_card_error(exception_object: Exception) -> bool:
    """
    True when the tag flickers out of range (very common with embedded tags).
    """
    error_message = str(exception_object).lower().replace("0x", "")
    return (
        "not responding to a reset" in error_message
        or "has been removed" in error_message
        or "further communication is not possible" in error_message
        or ERROR_CARD_UNRESPONSIVE_HEX in error_message
        or ERROR_CARD_REMOVED_HEX in error_message
        or isinstance(exception_object, NoCardException)
    )


def read_type2_tag_memory_pages(connection_object, start_page_inclusive=0x00, end_page_inclusive=0x40):
    """
    Reads Type 2 tag memory in 4-byte pages using PC/SC READ BINARY:
        CLA=0xFF, INS=0xB0, P1=0x00, P2=page, Le=0x04
    Returns a bytes object of concatenated pages, or None if unsupported.
    """
    complete_memory_dump = bytearray()

    for page_number in range(start_page_inclusive, end_page_inclusive + 1):
        apdu_read_one_page = [
            0xFF,          # CLA (proprietary for PC/SC readers)
            0xB0,          # INS (Read Binary)
            0x00,          # P1
            page_number,   # P2 = page number
            0x04           # Le = 4 bytes per page
        ]

        page_data_bytes, sw1, sw2 = connection_object.transmit(
            apdu_read_one_page)
        if (sw1, sw2) != (STATUS_SUCCESS_SW1, STATUS_SUCCESS_SW2) or len(page_data_bytes) != 4:
            return None

        complete_memory_dump.extend(page_data_bytes)

    return bytes(complete_memory_dump)


def extract_ndef_message_from_type2_memory(type2_memory_bytes: bytes) -> bytes | None:
    """
    Type 2 tags store NDEF inside TLVs starting at byte offset 16 (page 4).
    We scan TLVs to find NDEF TLV (0x03) and return its payload (the NDEF message bytes).
    """
    if not type2_memory_bytes or len(type2_memory_bytes) < 16:
        return None

    current_index = 16  # page 4
    memory_length = len(type2_memory_bytes)

    while current_index < memory_length:
        tlv_tag = type2_memory_bytes[current_index]
        current_index += 1

        if tlv_tag == 0x00:
            # NULL TLV: padding
            continue

        if tlv_tag == 0xFE:
            # Terminator TLV
            return None

        if current_index >= memory_length:
            return None

        # TLV length (short form only is typical for small payloads)
        tlv_length = type2_memory_bytes[current_index]
        current_index += 1

        # Long-form length (0xFF) exists, handle it just in case
        if tlv_length == 0xFF:
            if current_index + 1 >= memory_length:
                return None
            tlv_length = (
                type2_memory_bytes[current_index] << 8) | type2_memory_bytes[current_index + 1]
            current_index += 2

        if current_index + tlv_length > memory_length:
            return None

        tlv_value = type2_memory_bytes[current_index:current_index + tlv_length]
        current_index += tlv_length

        if tlv_tag == 0x03:
            # NDEF Message TLV
            return tlv_value

    return None


# =========================
# NDEF DECODING (URL/TEXT/DATA)
# =========================

TNF_WELL_KNOWN = 0x01
TNF_MIME_MEDIA = 0x02
TNF_ABSOLUTE_URI = 0x03
TNF_EXTERNAL_TYPE = 0x04

NDEF_TYPE_URI = b"U"
NDEF_TYPE_TEXT = b"T"

URI_PREFIX_TABLE = [
    "", "http://www.", "https://www.", "http://", "https://",
    "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
    "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
    "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
    "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
    "btgoep://", "tcpobex://", "irdaobex://", "file://",
    "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:",
    "urn:epc:", "urn:nfc:"
]


def bytes_look_like_text(payload_bytes: bytes) -> bool:
    """
    Heuristic: is it mostly printable ASCII/UTF-8-ish?
    """
    if not payload_bytes:
        return True
    try:
        decoded = payload_bytes.decode("utf-8")
    except Exception:
        return False

    printable = set(string.printable)
    printable_count = sum(1 for ch in decoded if ch in printable)
    return printable_count / max(1, len(decoded)) > 0.85


def format_payload_for_humans(payload_bytes: bytes) -> str:
    """
    If it looks like text, return decoded text. Otherwise return hex.
    """
    if payload_bytes is None:
        return ""
    if len(payload_bytes) == 0:
        return "(empty)"
    if bytes_look_like_text(payload_bytes):
        return payload_bytes.decode("utf-8", errors="replace")
    return "HEX: " + " ".join(f"{b:02X}" for b in payload_bytes)


def parse_ndef_message(ndef_message_bytes: bytes):
    """
    Parses a full NDEF message into a list of records (dicts).
    Supports:
      - URI (Well-known 'U')
      - Text (Well-known 'T')
      - MIME media (custom data, e.g. application/json)
      - External type (custom data, e.g. your.domain:duckdata)
      - Absolute URI (rare)
    """
    if not ndef_message_bytes:
        return []

    records = []
    index = 0

    while index < len(ndef_message_bytes):
        header_byte = ndef_message_bytes[index]
        index += 1

        message_begin = (header_byte & 0x80) != 0
        message_end = (header_byte & 0x40) != 0
        short_record = (header_byte & 0x10) != 0
        id_length_present = (header_byte & 0x08) != 0
        type_name_format = header_byte & 0x07

        if index >= len(ndef_message_bytes):
            break

        type_length = ndef_message_bytes[index]
        index += 1

        if short_record:
            if index >= len(ndef_message_bytes):
                break
            payload_length = ndef_message_bytes[index]
            index += 1
        else:
            if index + 3 >= len(ndef_message_bytes):
                break
            payload_length = (
                (ndef_message_bytes[index] << 24)
                | (ndef_message_bytes[index + 1] << 16)
                | (ndef_message_bytes[index + 2] << 8)
                | ndef_message_bytes[index + 3]
            )
            index += 4

        record_id_length = 0
        if id_length_present:
            if index >= len(ndef_message_bytes):
                break
            record_id_length = ndef_message_bytes[index]
            index += 1

        if index + type_length > len(ndef_message_bytes):
            break
        record_type_bytes = ndef_message_bytes[index:index + type_length]
        index += type_length

        if index + record_id_length > len(ndef_message_bytes):
            break
        record_id_bytes = ndef_message_bytes[index:index + record_id_length]
        index += record_id_length

        if index + payload_length > len(ndef_message_bytes):
            break
        record_payload_bytes = ndef_message_bytes[index:index + payload_length]
        index += payload_length

        record_info = {
            "tnf": type_name_format,
            "type_bytes": record_type_bytes,
            "id_bytes": record_id_bytes,
            "payload_bytes": record_payload_bytes,
        }

        # ---- Friendly decoding paths ----
        if type_name_format == TNF_WELL_KNOWN and record_type_bytes == NDEF_TYPE_URI:
            # Payload: [prefix_code][rest_of_uri]
            prefix_code = record_payload_bytes[0] if len(
                record_payload_bytes) > 0 else 0
            uri_rest = record_payload_bytes[1:].decode(
                "utf-8", errors="replace")
            prefix = URI_PREFIX_TABLE[prefix_code] if prefix_code < len(
                URI_PREFIX_TABLE) else ""
            record_info["kind"] = "URL"
            record_info["value"] = prefix + uri_rest

        elif type_name_format == TNF_WELL_KNOWN and record_type_bytes == NDEF_TYPE_TEXT:
            # Payload: [status][lang...][text...]
            if len(record_payload_bytes) >= 1:
                status_byte = record_payload_bytes[0]
                language_code_length = status_byte & 0x3F
                text_bytes = record_payload_bytes[1 + language_code_length:]
                record_info["kind"] = "TEXT"
                record_info["value"] = text_bytes.decode(
                    "utf-8", errors="replace")
            else:
                record_info["kind"] = "TEXT"
                record_info["value"] = ""

        elif type_name_format == TNF_MIME_MEDIA:
            # Type field is ASCII MIME type, payload is the data
            mime_type = record_type_bytes.decode("utf-8", errors="replace")
            record_info["kind"] = "DATA(MIME)"
            record_info["mime_type"] = mime_type
            record_info["value"] = format_payload_for_humans(
                record_payload_bytes)

        elif type_name_format == TNF_EXTERNAL_TYPE:
            # Type field is ASCII like "your.domain:thing"
            external_type = record_type_bytes.decode("utf-8", errors="replace")
            record_info["kind"] = "DATA(EXTERNAL)"
            record_info["external_type"] = external_type
            record_info["value"] = format_payload_for_humans(
                record_payload_bytes)

        elif type_name_format == TNF_ABSOLUTE_URI:
            absolute_uri = record_type_bytes.decode("utf-8", errors="replace")
            record_info["kind"] = "ABSOLUTE_URI"
            record_info["uri"] = absolute_uri
            record_info["value"] = format_payload_for_humans(
                record_payload_bytes)

        else:
            record_info["kind"] = "UNKNOWN"
            record_info["value"] = format_payload_for_humans(
                record_payload_bytes)

        records.append(record_info)

        if message_end:
            break

    return records


def print_ndef_records_friendly(ndef_message_bytes: bytes):
    records = parse_ndef_message(ndef_message_bytes)
    if not records:
        print("Stored data: (no NDEF records found)")
        return

    print("Stored data (NDEF records):")
    for record_index, record in enumerate(records, start=1):
        kind = record.get("kind", "UNKNOWN")

        if kind == "URL":
            print(f"  {record_index}. URL: {record['value']}")

        elif kind == "TEXT":
            print(f"  {record_index}. Text: {record['value']}")

        elif kind == "DATA(MIME)":
            print(
                f"  {record_index}. Data (MIME: {record.get('mime_type', '')}): {record['value']}")
            if record.get('mime_type', '') == "application/json":
                data = json.loads(record['value'].replace('“', '"').replace(
                    '”', '"').replace('‘', "'").replace('’', "'"))

                print(data)
        elif kind == "DATA(EXTERNAL)":
            print(
                f"  {record_index}. Data (External: {record.get('external_type', '')}): {record['value']}")

        elif kind == "ABSOLUTE_URI":
            print(
                f"  {record_index}. Absolute URI ({record.get('uri', '')}): {record['value']}")

        else:
            record_type_preview = record.get("type_bytes", b"")
            print(
                f"  {record_index}. Unknown record type={record_type_preview!r}: {record['value']}")


# =========================
# OBSERVER
# =========================

class NFCReaderObserver(CardObserver):
    def update(self, observable, actions):
        cards_added, cards_removed = actions

        for detected_card in cards_added:
            time.sleep(0.10)

            try:
                card_connection = detected_card.createConnection()
                card_connection.connect()

                uid_bytes, sw1, sw2 = card_connection.transmit(
                    APDU_GET_CARD_UID)
                if (sw1, sw2) != (STATUS_SUCCESS_SW1, STATUS_SUCCESS_SW2):
                    return

                card_uid_hex_string = "".join(f"{b:02X}" for b in uid_bytes)
                print("\nDuck detected!")
                print("Card UID:", card_uid_hex_string)

                type2_memory_dump_bytes = read_type2_tag_memory_pages(
                    card_connection, 0x00, 0x40)
                if type2_memory_dump_bytes is None:
                    print(
                        "Stored data: (could not read Type 2 memory from this reader/tag)")
                    return

                ndef_message_bytes = extract_ndef_message_from_type2_memory(
                    type2_memory_dump_bytes)
                if ndef_message_bytes is None:
                    print("Stored data: (no NDEF message found)")
                    return

                print_ndef_records_friendly(ndef_message_bytes)

            except (CardConnectionException, NoCardException) as connection_error:
                if not is_transient_card_error(connection_error):
                    print("Connection error:", connection_error)

        for _ in cards_removed:
            print("Duck removed.")


def main():
    available_readers = readers()
    if not available_readers:
        print("No NFC readers found.")
        return

    print("Reader ready. Tap a duck.\n")

    card_monitor = CardMonitor()
    observer = NFCReaderObserver()
    card_monitor.addObserver(observer)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        card_monitor.deleteObserver(observer)


if __name__ == "__main__":
    main()