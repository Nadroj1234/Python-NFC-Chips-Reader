from smartcard.System import readers

def get_uid(reader_index=0):
    r = readers()[reader_index]
    connection = r.createConnection()
    connection.connect()

    # APDU command to get UID
    GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]

    data, sw1, sw2 = connection.transmit(GET_UID)

    if (sw1, sw2) == (0x90, 0x00):
        uid = ''.join(f"{byte:02X}" for byte in data)
        print(f"UID: {uid}")
        return uid
    else:
        print(f"Failed to get UID: {sw1:02X} {sw2:02X}")
        return None


if __name__ == "__main__":
    get_uid(0)