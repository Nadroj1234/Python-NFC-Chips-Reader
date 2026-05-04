import json
import time
from typing import Optional

from nfc_portal import NfcPortalManager, PortalState


LEFT_READER_MATCH = "0"
RIGHT_READER_MATCH = "1"


def classify_portal_side(reader_name: str) -> Optional[str]:
    if LEFT_READER_MATCH in reader_name:
        return "left"
    if RIGHT_READER_MATCH in reader_name:
        return "right"
    return None


# 🔥 NEW: Dump all raw blocks
def dump_all_blocks(state: PortalState):
    print("\n--- RAW MIFARE CLASSIC DUMP (Blocks 0–63) ---")

    # Check if memory is available
    if not hasattr(state, "memory_pages") or not state.memory_pages:
        print("❌ No raw memory available from this reader/state")
        return

    # Flatten pages into raw byte list
    raw_bytes = []
    for page in state.memory_pages:
        raw_bytes.extend(page)

    # Split into 16-byte blocks
    blocks = [raw_bytes[i:i+16] for i in range(0, len(raw_bytes), 16)]

    # Print up to 64 blocks
    for i, block in enumerate(blocks[:64]):
        hex_data = " ".join(f"{b:02X}" for b in block)
        print(f"Block {i:02}: {hex_data}")


def print_full_state_dump(state: PortalState):
    print("\n" + "=" * 60)
    print(f"Reader: {state.reader_name}")
    print(f"UID: {state.uid_hex}")
    print(f"Has Tag: {state.has_tag()}")
    print("-" * 60)

    if state.skylander_info:
        print("Detected Toy Type: Skylander")
        print(f"Skylander: {state.skylander_info.name}")
        print(f"Character ID: {state.skylander_info.character_id}")
        print(f"Variant ID: {state.skylander_info.variant_id}")
        print(f"Decode Strategy: {state.skylander_info.decode_strategy}")
        print(f"Block 1: {state.skylander_info.block_hex(1)}")

        # 🔥 NEW: Full block dump
        dump_all_blocks(state)

        print("=" * 60)
        return

    if not state.ndef_records:
        print("No NDEF records found.")

        # 🔥 Even if no NDEF, still try raw dump
        dump_all_blocks(state)

        print("=" * 60)
        return

    for i, record in enumerate(state.ndef_records, start=1):
        print(f"\nRecord #{i}")
        print(f"  Kind: {record.kind}")
        print(f"  Type Text: {record.type_text}")
        print(f"  MIME Type: {record.mime_type}")
        print(f"  External Type: {record.external_type}")
        print(f"  Text Value: {record.text_value}")

        hex_preview = " ".join(f"{b:02X}" for b in record.payload_bytes[:64])
        if len(record.payload_bytes) > 64:
            hex_preview += " ..."
        print(f"  Raw Bytes (hex): {hex_preview}")

        try:
            parsed_json = record.as_json()
            print("  Parsed JSON:", json.dumps(parsed_json, indent=4))
        except Exception:
            pass

    print("\nResolved Name:", state.get_name())

    # 🔥 Also dump blocks for NDEF tags
    dump_all_blocks(state)

    print("=" * 60)


class ToyInteractionController:
    def __init__(self):
        self.left: Optional[PortalState] = None
        self.right: Optional[PortalState] = None
        self.last_pair_key: Optional[str] = None

    def on_state_changed(self, old_state: PortalState, new_state: PortalState):
        side = classify_portal_side(new_state.reader_name)
        if side is None:
            return

        if new_state.has_tag():
            print_full_state_dump(new_state)
        else:
            print(f"\nTag removed from {new_state.reader_name}")

        if side == "left":
            self.left = new_state if new_state.has_tag() else None
        else:
            self.right = new_state if new_state.has_tag() else None

        self._try_note_pair()

    def _try_note_pair(self):
        if not self.left or not self.right:
            self.last_pair_key = None
            return

        pair_key = f"{self.left.uid_hex}|{self.right.uid_hex}"
        if pair_key == self.last_pair_key:
            return

        self.last_pair_key = pair_key

        toy1_name = self.left.get_name()
        toy2_name = self.right.get_name()
        print(f"\n{toy1_name} is next to {toy2_name}")


def print_reader_names_once():
    from smartcard.System import readers

    print("Detected readers:")
    for reader in readers():
        print(" -", reader)
    print()


def main():
    print_reader_names_once()

    controller = ToyInteractionController()

    manager = NfcPortalManager(
        poll_interval_seconds=0.20,
        memory_page_end_inclusive=0x40,
        on_state_changed=controller.on_state_changed,
    )

    manager.start()

    try:
        print("Ready. Put a Skylanders toy on the reader...\n(CTRL+C to quit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
        print("\nStopped.")


if __name__ == "__main__":
    main()