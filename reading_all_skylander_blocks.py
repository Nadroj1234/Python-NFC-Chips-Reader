from smartcard.System import readers

# Common keys to try (you can add more if needed)
KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],  # default
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
]

def load_key(connection, key, key_number=0):
    # Load key into reader
    load_cmd = [0xFF, 0x82, 0x00, key_number, 0x06] + key
    _, sw1, sw2 = connection.transmit(load_cmd)
    return (sw1, sw2) == (0x90, 0x00)

def authenticate(connection, block, key_number=0):
    auth_cmd = [
        0xFF, 0x86, 0x00, 0x00, 0x05,
        0x01, 0x00, block, 0x60, key_number  # 0x60 = Key A
    ]
    _, sw1, sw2 = connection.transmit(auth_cmd)
    return (sw1, sw2) == (0x90, 0x00)

def read_block(connection, block):
    read_cmd = [0xFF, 0xB0, 0x00, block, 0x10]
    data, sw1, sw2 = connection.transmit(read_cmd)
    if (sw1, sw2) == (0x90, 0x00):
        return data
    return None

def read_skylander(reader_index=0):
    r = readers()[reader_index]
    conn = r.createConnection()
    conn.connect()

    print("Connected to reader")

    full_dump = []

    for sector in range(16):
        print(f"\n=== Sector {sector} ===")

        # Try each key until one works
        authenticated = False
        for key in KEYS:
            if not load_key(conn, key):
                continue

            if authenticate(conn, sector * 4):
                print(f"Authenticated with key: {key}")
                authenticated = True
                break

        if not authenticated:
            print("❌ Failed to authenticate sector")
            full_dump.extend([None]*4)
            continue

        # Read 4 blocks in sector
        for block_offset in range(4):
            block_num = sector * 4 + block_offset
            data = read_block(conn, block_num)

            if data:
                hex_data = ' '.join(f"{b:02X}" for b in data)
                print(f"Block {block_num:02}: {hex_data}")
                full_dump.append(data)
            else:
                print(f"Block {block_num:02}: ❌ Read failed")
                full_dump.append(None)

    return full_dump


if __name__ == "__main__":
    dump = read_skylander()