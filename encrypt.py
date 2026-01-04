# encrypt.py
with open("fscan.exe", "rb") as f:
    data = f.read()
with open("fscan.enc", "wb") as f:
    f.write(bytearray([b ^ 0x42 for b in data]))
