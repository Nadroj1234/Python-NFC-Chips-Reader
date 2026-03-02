import time
import json
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


def print_full_state_dump(state: PortalState):
    print("\n" + "=" * 60)
    print(f"Reader: {state.reader_name}")
    print(f"UID: {state.uid_hex}")
    print(f"Has Tag: {state.has_tag()}")
    print("-" * 60)

    if not state.ndef_records:
        print("No NDEF records found.")
        print("=" * 60)
        return

    for i, record in enumerate(state.ndef_records, start=1):
        print(f"\nRecord #{i}")
        print(f"  Kind: {record.kind}")
        print(f"  Type Text: {record.type_text}")
        print(f"  MIME Type: {record.mime_type}")
        print(f"  External Type: {record.external_type}")
        print(f"  Text Value: {record.text_value}")

        # Raw payload preview
        hex_preview = " ".join(f"{b:02X}" for b in record.payload_bytes[:64])
        if len(record.payload_bytes) > 64:
            hex_preview += " ..."
        print(f"  Raw Bytes (hex): {hex_preview}")

        # Try JSON parse
        try:
            parsed_json = record.as_json()
            print("  Parsed JSON:", json.dumps(parsed_json, indent=4))
        except Exception:
            pass

    print("\nResolved Duck Name:", state.get_name())
    print("=" * 60)


class DuckInteractionController:
    def __init__(self):
        self.left: Optional[PortalState] = None
        self.right: Optional[PortalState] = None
        self.last_pair_key: Optional[str] = None

    def on_state_changed(self, old_state: PortalState, new_state: PortalState):
        side = classify_portal_side(new_state.reader_name)
        if side is None:
            return

        # Log EVERYTHING
        if new_state.has_tag():
            print_full_state_dump(new_state)
        else:
            print(f"\nTag removed from {new_state.reader_name}")

        if side == "left":
            self.left = new_state if new_state.has_tag() else None
        else:
            self.right = new_state if new_state.has_tag() else None

        self._try_greet()

    def _try_greet(self):
        if not self.left or not self.right:
            self.last_pair_key = None
            return

        pair_key = f"{self.left.uid_hex}|{self.right.uid_hex}"
        if pair_key == self.last_pair_key:
            return

        self.last_pair_key = pair_key

        duck1_name = self.left.get_name()
        duck2_name = self.right.get_name()

        print(f"\n🦆 {duck1_name} says hello to {duck2_name} 👋")


def print_reader_names_once():
    from smartcard.System import readers
    print("Detected readers:")
    for r in readers():
        print(" -", r)
    print()


def main():
    print_reader_names_once()

    controller = DuckInteractionController()

    manager = NfcPortalManager(
        poll_interval_seconds=0.20,
        memory_page_end_inclusive=0x40,
        on_state_changed=controller.on_state_changed,
    )

    manager.start()

    try:
        print("Ready. Put ducks on the portals...\n(CTRL+C to quit)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
        print("\nStopped.")


if __name__ == "__main__":
    main()
