""" Library for creating a Multisignature single address wallet + signature tool """

from bit import Key, MultiSig
from bit import PrivateKey, PrivateKeyTestnet, MultiSigTestnet, utils


class TestnetMultisig:

    def __init__(self,m,n):
        # multisig m/n
        self.m = m
        self.n = n
        self.priv = []
        self.pub = []
        self.wif = []
        self.pubhex = []
        self.multisig = None
        self.recipients = []

    def create_multisig(self,first_private,public_list):
        public_list_bin = []
        for i in public_list:
            public_list_bin.append(utils.hex_to_bytes(i))
        multisig = MultiSigTestnet(PrivateKeyTestnet(first_private), set(public_list_bin), self.m)
        self.multisig = multisig
        self.pubhex = public_list
        self.pub = public_list_bin
        self.wif.append(first_private)
        self.priv.append(PrivateKeyTestnet(first_private))
        multisig_data = {'public_keys': self.pubhex,
                               'address' : multisig.address,
                               'segwit_address' : multisig.segwit_address,
                               'required_keys': self.m,
                               'total_keys' : self.n,
                               }
        return multisig_data

    def add_recipient(self, recipient):
        # format: ('tb1qu8l6t60jcv8zhpncyx0h9c2d8cfj3n73qda3cg', 0.0003)
        b = list(recipient)
        b.append('btc')
        b = tuple(b)
        self.recipients.append(b)
        return self.recipients


    def get_transaction(self,minerfee):
        tx = self.multisig.create_transaction(self.recipients,replace_by_fee=True,fee=minerfee)
        return tx


    def sign_transaction(self,partial,priv_n):
        # take partial signed and add signature
        multisig_n = MultiSigTestnet(PrivateKeyTestnet(priv_n), set(self.pub), self.m)
        tx_n = multisig_n.sign_transaction(partial)
        return tx_n



