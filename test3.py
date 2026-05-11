import nfc

def on_connect(tag):
    print("\n🎮 NFC tag detected!")
    print("Tag type:", tag.type)

    try:
        print("UID:", tag.identifier.hex())
    except:
        print("Could not read UID")

    # Return True keeps connection open briefly, then disconnects
    return True


def main():
    print("Waiting for Skylander / NFC tag... (Press Ctrl+C to stop)")

    clf = nfc.ContactlessFrontend('usb')

    while True:
        clf.connect(rdwr={
            'on-connect': on_connect
        })

if __name__ == "__main__":
    main()