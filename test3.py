from smartcard.System import readers

r = readers()[0]
conn = r.createConnection()
conn.connect()

# Load default key FF FF FF FF FF FF into slot 0
load_key = [0xFF, 0x82, 0x00, 0x00, 0x06] + [0xFF]*6
conn.transmit(load_key)

# Try to authenticate block 0
auth = [0xFF, 0x86, 0x00, 0x00, 0x05,
        0x01, 0x00, 0x00, 0x60, 0x00]

resp, sw1, sw2 = conn.transmit(auth)

print(f"Auth result: {hex(sw1)} {hex(sw2)}")