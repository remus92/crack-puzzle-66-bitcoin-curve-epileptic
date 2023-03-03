import asyncio
import base58
import concurrent.futures
import hashlib
import random
import ecdsa

def private_key_to_WIF(private_key):
    private_key = bytes.fromhex(private_key)
    extended_key = b"\x80" + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode("utf-8")

def private_key_to_address(private_key, compressed=True):
    private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1).verifying_key
    if compressed:
        public_key = private_key.to_string(encoding='compressed')
    else:
        public_key = b"\x04" + private_key.to_string()
    sha256_bpk = hashlib.sha256(public_key)
    ripemd160_bpk = hashlib.new("ripemd160", sha256_bpk.digest()).digest()
    network_byte = b"\x00"
    extended_ripemd160 = network_byte + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum

    # verifica daca trebuie sa opresti si sa repornesti algoritmul
    if private_key_to_address.counter is None:
        private_key_to_address.counter = 0
        private_key_to_address.last_stop = 0
    private_key_to_address.counter += 1
    if private_key_to_address.counter - private_key_to_address.last_stop >= 1000000:
        ecdsa.ecdsa.generator_secp256k1 = ecdsa.SECP256k1.generator
        private_key_to_address.last_stop = private_key_to_address.counter

    return base58.b58encode(binary_address).decode("utf-8")

private_key_to_address.counter = None
private_key_to_address.last_stop = None

async def find_private_key(target_address):
    counter = 0
    while True:
        private_key_int = random.randint(0x30000000000000000, 0x3ffffffffffffffff)
        private_key = hex(private_key_int)[2:].zfill(64)
        try:
            address = private_key_to_address(private_key)
            if address == target_address:
                wif = private_key_to_WIF(private_key)
                print(f"Private Key (HEX): {private_key}")
                print(f"Private Key (WIF): {wif}")
                print(f"Bitcoin Address (Compressed): {address}\n")
                return counter
        except Exception:
            pass
        counter += 1
        if counter % 1000 == 0:
            print(f"\rCurrent number of private keys generated: {counter}, {private_key} ", end="")

if __name__ == '__main__':
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
    loop = asyncio.get_event_loop()
    tasks = [loop.create_task(find_private_key(target_address)) for i in range(2000000)]
    results = loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    for result in results:
        if isinstance(result, Exception):
            print(f"An error occurred: {result}")
        else:
            print(f"Task completed with result: {result}")
