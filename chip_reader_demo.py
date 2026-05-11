from smartcard.System import readers

# Common MIFARE Classic keys
KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
]


def load_key(conn, key, slot=0):
    cmd = [0xFF, 0x82, 0x00, slot, 0x06] + key
    _, sw1, sw2 = conn.transmit(cmd)
    return (sw1, sw2) == (0x90, 0x00)


def authenticate(conn, block, slot=0):
    cmd = [
        0xFF, 0x86, 0x00, 0x00, 0x05,
        0x01, 0x00, block, 0x60, slot
    ]
    _, sw1, sw2 = conn.transmit(cmd)
    return (sw1, sw2) == (0x90, 0x00)


def read_block(conn, block):
    cmd = [0xFF, 0xB0, 0x00, block, 0x10]
    data, sw1, sw2 = conn.transmit(cmd)
    if (sw1, sw2) == (0x90, 0x00):
        return data
    return None


def dump_card():
    rlist = readers()

    if not rlist:
        print("❌ No readers found")
        return

    reader = rlist[0]
    conn = reader.createConnection()
    conn.connect()

    print(f"Connected to: {reader}")

    # Get UID
    uid_cmd = [0xFF, 0xCA, 0x00, 0x00, 0x00]
    uid, sw1, sw2 = conn.transmit(uid_cmd)

    if (sw1, sw2) == (0x90, 0x00):
        print("UID:", " ".join(f"{b:02X}" for b in uid))

    print("\n--- Dumping 64 blocks ---\n")

    for sector in range(16):
        block_start = sector * 4
        authenticated = False

        for key in KEYS:
            load_key(conn, key)

            if authenticate(conn, block_start):
                print(f"Sector {sector}: Auth OK with key {key}")
                authenticated = True
                break

        if not authenticated:
            print(f"Sector {sector}: ❌ Auth failed")
            continue

        for i in range(4):
            block = block_start + i
            data = read_block(conn, block)

            if data:
                hex_data = " ".join(f"{b:02X}" for b in data)
                print(f"Block {block:02}: {hex_data}")
            else:
                print(f"Block {block:02}: ❌ Read failed")


if __name__ == "__main__":
    dump_card()