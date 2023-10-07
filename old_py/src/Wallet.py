import hmac, hashlib
from mnemonic import Mnemonic
from AddressGenerator import pub_from_prv, decompress_xy, compress_xy
from AddressGenerator import __double_and_add as double_and_add
from AddressGenerator import __point_add as point_add

from Constants import N as FIELD_SIZE
from Constants import G
from Crypto.Hash import RIPEMD160
from base58 import b58encode, b58decode


class HDWallet:
    def __init__(
        self, using, seed=None, key=None, words=None, passphrase=None, lang=None
    ):
        if using == "seed":
            if seed is None:
                raise Exception("using='seed' requires 'seed'")
            if (
                key is not None
                or words is not None
                or passphrase is not None
                or lang is not None
            ):
                raise Exception("using='seed' takes no additional arguments")
            self._seed = bytes.fromhex(seed)
            self._import_from_seed(self._seed)
        elif using == "key":
            if key is None:
                raise Exception("using='key' requires 'key'")
            if (
                seed is not None
                or words is not None
                or passphrase is not None
                or lang is not None
            ):
                raise Exception("using='key' takes no additional arguments")
            self._import_from_extended_key(key)
        elif using == "words":
            if words is None:
                raise Exception("using='words' requires 'words'")
            if seed is not None or key is not None:
                raise Exception(
                    "using='words' cannot have 'seed' or 'key' as arguments"
                )
            if passphrase is None:
                passphrase = ""
            if lang is None:
                lang = "english"

            mnemo = Mnemonic(lang)
            self._seed = mnemo.to_seed(words, passphrase=passphrase)
            self._import_from_seed(self._seed)
        else:
            raise Exception(f"Invalid 'using={using}'")

    def _parse_hash(self, hash):
        return hash[:64], pub_from_prv(int(hash[:64], 16)), hash[-64:]

    def _derive_child(self, parent, idx, hardened):
        # parent = [prv, pub, chain]
        if self._master_prv is not None:
            if hardened:
                prv_bytes = int(parent[0], 16).to_bytes(33, "big")
                idx += int("80000000", 16)
                idx_bytes = idx.to_bytes(4, "big")

                msg = prv_bytes + idx_bytes
                hash = hmac.new(
                    bytes.fromhex(parent[2]),
                    msg=msg,
                    digestmod=hashlib.sha512,
                ).digest()
            else:
                pub_bytes = int(parent[1], 16).to_bytes(33, "big")
                idx_bytes = idx.to_bytes(4, "big")

                msg = pub_bytes + idx_bytes
                hash = hmac.new(
                    bytes.fromhex(parent[2]),
                    msg=msg,
                    digestmod=hashlib.sha512,
                ).digest()

            h, chain = hash[0:32], hash[32:]

            prv = (int.from_bytes(h, "big") + int(parent[0], 16)) % FIELD_SIZE
            prv_str = prv.to_bytes(32, "big").hex()
            if int.from_bytes(h, "big") >= FIELD_SIZE or prv == 0:
                return [None, None, None]
            pub_str = pub_from_prv(prv)
            assert len(pub_str) == 66

            prv = (int.from_bytes(h, "big") + int(parent[0], 16)) % FIELD_SIZE
            prv_str = prv.to_bytes(32, "big").hex()
            if int.from_bytes(h, "big") >= FIELD_SIZE or prv == 0:
                return [None, None, None]
            pub_str = pub_from_prv(prv)
            assert len(pub_str) == 66
        else:  # Pub -> Pub
            pub_bytes = int(parent[1], 16).to_bytes(33, "big")
            idx_bytes = idx.to_bytes(4, "big")

            msg = pub_bytes + idx_bytes
            hash = hmac.new(
                bytes.fromhex(parent[2]),
                msg=msg,
                digestmod=hashlib.sha512,
            ).digest()
            h, chain = hash[0:32], hash[32:]
            prv_str = None
            d = int.from_bytes(h, "big")
            if d >= FIELD_SIZE:
                return [None, None, None]
            a = double_and_add(G, d)
            if a is [None, None]:
                return [None, None, None]
            parent_xy = decompress_xy(self._master_pub)
            child_xy = point_add(a, parent_xy)
            pub_str = compress_xy(child_xy)
            assert len(pub_str) == 66

        return [
            prv_str,
            pub_str,
            chain.hex(),
        ]

    def _serialize_fingerprint(self, pub):
        a = hashlib.sha256(bytes.fromhex(pub)).digest()
        h = RIPEMD160.new(a).hexdigest()
        return h[:8]

    def _import_from_seed(self, seed):
        hash = hmac.new(
            bytes(f"Bitcoin seed", "utf-8"),
            msg=seed,
            digestmod=hashlib.sha512,
        ).hexdigest()

        (
            self._master_prv,
            self._master_pub,
            self._master_chain_code,
        ) = self._parse_hash(hash)

        self._master_depth = 0
        self._master_fingerprint = "00000000"
        self._master_child_number = 0

    def _import_from_extended_key(self, key):
        b58 = b58decode(key)
        checksum = b58[-4:]
        data = b58[:-4]

        test = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        if test != checksum:
            raise Exception("couldn't initialize from key")

        if len(data) != 78:
            raise Exception("couldn't initialize from key")

        version = data[0:4]
        if version == b"\x04\x88\xAD\xE4":  # xpriv
            self._master_pub = None
            self._master_prv = data[45:].hex()
        elif version == b"\x04\x88\xB2\x1E":  # xpub
            self._master_pub = data[45:].hex()
            self._master_prv = None
        else:
            raise Exception("couldn't initialize from key")

        self._master_depth = int.from_bytes(data[4:5], "big")
        self._master_fingerprint = data[5:9].hex()
        self._master_child_number = int.from_bytes(data[9:13], "big")
        self._master_chain_code = data[13:45].hex()

    def _extended_format_key(
        self, is_private, depth, parent_fingerprint, is_hardened, idx, chain_code, key
    ):
        version = bytes.fromhex("0488ADE4") if is_private else bytes.fromhex("0488B21E")
        depth_bytes = depth.to_bytes(1, "big")
        child_number = ((idx + int("80000000", 16)) if is_hardened else (idx)).to_bytes(
            4, "big"
        )
        formatted_key = (
            b"\x00" + bytes.fromhex(key) if is_private else bytes.fromhex(key)
        )

        data = (
            version
            + depth_bytes
            + bytes.fromhex(parent_fingerprint)
            + child_number
            + bytes.fromhex(chain_code)
            + formatted_key
        )

        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        return b58encode(data + checksum).decode("utf-8")

    def get(self, path):
        operations = path.split("/")
        operations.reverse()

        is_private = operations.pop() == "m"
        if self._master_prv is None and is_private:
            return "invalid path ~ can't derive private keys if built with xpub"

        depth = self._master_depth
        prev_fingerprint = self._master_fingerprint
        idx = self._master_child_number
        get_hardened = False
        node = [self._master_prv, self._master_pub, self._master_chain_code]

        while len(operations) > 0:
            prev_fingerprint = self._serialize_fingerprint(pub=node[1])
            depth += 1
            op = operations.pop()
            get_hardened = op[-1] == "'"
            if self._master_prv is None and get_hardened:
                return (
                    "invalid path ~ can't derive hardened children if built with xpub"
                )
            idx = int(op) if not get_hardened else int(op[:-1])
            node = self._derive_child(node, idx, hardened=get_hardened)
        val = node[0] if is_private else node[1]
        return self._extended_format_key(
            is_private=is_private,
            depth=depth,
            parent_fingerprint=prev_fingerprint,
            is_hardened=get_hardened,
            idx=idx,
            chain_code=node[2],
            key=val,
        )
