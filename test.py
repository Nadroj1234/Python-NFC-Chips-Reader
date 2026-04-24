from smartcard.System import readers

def send_escape_command(connection, command):
    apdu = [0xFF, 0x00, 0x00, 0x00, len(command)] + command
    return connection.transmit(apdu)

def write_block_0_gen1(reader_index, new_uid):
    r = readers()[reader_index]
    connection = r.createConnection()
    connection.connect()

    # Send backdoor sequence for "Gen1" / backdoored cards
    send_escape_command(connection, [0x50, 0x00]) # HALT
    send_escape_command(connection, [0x40])        # WUPC
    send_escape_command(connection, [0x43])        # Backdoor open

    # Calculate BCC
    bcc = new_uid[0] ^ new_uid[1] ^ new_uid[2] ^ new_uid[3]

    # Construct Block 0 data
    block0_data = new_uid + [bcc, 0x08, 0x40] + [0x00] * 9

    # Write Block 0
    write_apdu = [0xFF, 0xD6, 0x00, 0x00, 0x10] + block0_data
    response, sw1, sw2 = connection.transmit(write_apdu)

    return response, sw1, sw2

if __name__ == "__main__":
    new_uid = [0xEF, 0x7D, 0x5F, 0xB8]
    response, sw1, sw2 = write_block_0_gen1(0, new_uid)
    print(f"Response: {response}, Status: {sw1:02X} {sw2:02X}")   