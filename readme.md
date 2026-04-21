# nfc card/chip reader demo

This was an ai generated program created as a test of [cryptnox card readers](https://www.amazon.com/dp/B0DVM5WHY6?ref=ppx_yo2ov_dt_b_fed_asin_title) for loading rubber duck data and reading Skylanders toys.  
The `nfc_portal.py` module can handle reading from multiple readers ("portals") and sending the data back to the calling code.  
`main.py` was created as a basic demo of interacting with the `NfcPortalManager` .

## Skylanders support

The app now includes a dedicated Skylanders reader path:

- reads the toy UID
- calculates the Skylanders sector keys from the UID
- authenticates and reads all 64 MIFARE Classic blocks
- extracts the character ID and variant ID from block 1
- resolves the figure name using the bundled `skylander_ids.md` catalog

If a tag is not an NDEF tag but is a supported Skylanders toy, `main.py` will print the toy name and IDs instead of showing it as empty data.

## Installation:

- in the terminal type `python -m venv venv`
- Activate the environment with (in windows) `venv/Scripts/activate`
- install the dependencies: `pip install -r requirements.txt`
