

import hashlib
import bech32
import bit
import secrets

class SingleWallet:
    def __init__(self, passwd=""):
        z = secrets.token_hex(256)
        h = hashlib.sha256(z.encode('utf-8')).hexdigest()
        self.entropy = h
        self.wallet = {}
        self.passwd = passwd
        return

    def _hash160(self, keyobj):
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(hashlib.sha256(keyobj.public_key).digest())
        return ripemd160.digest()

    def _bech32enc(self, ohash160, network='mainnet'):
        bechenc = bech32.encode("bc", 0, ohash160)
        return bechenc

    def _getsha256(self, z):
        return hashlib.sha256(z.encode('utf-8')).hexdigest()

    def get_jbok(self):
        """ define the key object """
        key = bit.Key.from_hex(self.entropy)

        """ private and public key values in hex format """
        hex_k = key.to_hex()
        hex_K = bit.utils.bytes_to_hex(key.public_key, True)

        """ calculate hash160 and bech32 address """
        bech32 = self._bech32enc(self._hash160(key), "mainnet")
        wallet = {
                  'private': hex_k,
                  'public': hex_K,
                  'WIF': key.to_wif(),
                  'p2pkh': key.address,
                  'p2wpkh-ps2h': key.segwit_address,
                  'p2wpkh': bech32
                  }
        self.wallet = wallet
        return wallet
