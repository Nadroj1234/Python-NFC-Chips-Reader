from smartcard.System import readers

def identify_card():
    r = readers()[0]
    conn = r.createConnection()
    conn.connect()

    # Get UID (safe, read-only)
    GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
    uid, sw1, sw2 = conn.transmit(GET_UID)

    print("UID:", ''.join(f"{b:02X}" for b in uid))
    print("SW:", hex(sw1), hex(sw2))

    # Try generic MIFARE test command
    GET_VERSION = [0xFF, 0x00, 0x00, 0x00, 0x00]
    resp, sw1, sw2 = conn.transmit(GET_VERSION)

    print("Reader response:", resp)
    print("SW:", hex(sw1), hex(sw2))


if __name__ == "__main__":
    identify_card()