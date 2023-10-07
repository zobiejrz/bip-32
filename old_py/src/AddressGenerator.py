import secrets, hashlib, base58check, sys, math
from Crypto.Hash import RIPEMD160
from Constants import *


# Helper functions
def __my_hex(n, signed=True):
    return hex(n)[2:]
    # val = abs(n)
    # if signed and (n & (1 << 255)) != 0:
    #   val = val - (1 << 256)
    # ret_str = hex(val).split("x")[1]
    # while len(ret_str) < 64:
    #   ret_str = f"0{ret_str}"
    # return ret_str


def __generate_private_key():
    x = secrets.randbits(256)
    while x >= N:
        x = secrets.randbits(256)
    return x


def __modInverse(b, m):
    g = math.gcd(b, m)
    if g != 1:
        return -1
    else:
        return pow(b, m - 2, m)


def __modDivide(a, b, m):
    a = a % m
    inv = __modInverse(b, m)
    if inv == -1:
        return (a // b) % m
    else:
        return (inv * a) % m


def __point_double(p, a=0, field=P):
    l = (3 * (p[0] ** 2) + a) * pow((2 * p[1]), field - 2, field)
    r_x = ((l**2) - p[0] - p[0]) % field
    r_y = ((l * (p[0] - r_x)) - p[1]) % field

    return [r_x, r_y]


def __point_add(p, q, a=0, field=P):
    l = (q[1] - p[1]) * pow((q[0] - p[0]), field - 2, field)
    r_x = ((l**2) - p[0] - q[0]) % field
    r_y = (l * (p[0] - r_x) - p[1]) % field

    return [r_x, r_y]


def __double_and_add(P, d, a=0, field=P):
    if d == 0:
        return PaI
    elif d == 1:
        return P
    elif d % 2 == 1:
        return __point_add(
            P, __double_and_add(P, (d - 1), a=a, field=field), a=a, field=field
        )
    else:
        return __double_and_add(
            __point_double(P, a=a, field=field), d // 2, a=a, field=field
        )


def __byte_len(i):
    n = len(hex(i)) - 2
    if i == 0:
        n = 1
    if i < 0:
        n -= 1
    return n


def __get_public_key_address(pubkey):
    # 2
    a = hashlib.sha256(bytes.fromhex(pubkey)).digest()

    # 3
    h = RIPEMD160.new(a)
    b = h.hexdigest()

    # 4
    c = f"00{b}"

    # 5
    d = hashlib.sha256(bytes.fromhex(c)).hexdigest()

    # 6
    e = hashlib.sha256(bytes.fromhex(d)).hexdigest()

    # 7
    checksum = e[:8]

    # 8
    binary_addr = f"{c}{checksum}"

    return base58check.b58encode(bytes.fromhex(binary_addr))


def __get_P2PKH_script_address(script):
    # 1- Get hash160 of script
    h = RIPEMD160.new(bytes.fromhex(script))
    fingerprint = h.hexdigest()

    # 2- Get checksum, first 4 bytes of SHA256(SHA256(fingerprint))
    d = hashlib.sha256(bytes.fromhex(fingerprint)).hexdigest()
    e = hashlib.sha256(bytes.fromhex(d)).hexdigest()
    checksum = e[:8]

    # 3- Base58 of 0x05 | fingerprint | checksum
    return base58check.b58encode(bytes.fromhex(f"05{fingerprint}{checksum}"))


def __private_to_wif(pk):
    a = f"80{pk}"
    b = hashlib.sha256(bytes.fromhex(a)).hexdigest()
    c = hashlib.sha256(bytes.fromhex(b)).hexdigest()
    checksum = c[:8]
    d = f"{a}{checksum}"
    e = str(base58check.b58encode(bytes.fromhex(d)), "UTF-8")
    assert e[0] == "5"
    return e


def __wif_to_private(wif):
    b = base58check.b58decode(wif.encode()).hex()
    fingerprint = b[:-8]
    d = hashlib.sha256(bytes.fromhex(fingerprint)).hexdigest()
    e = hashlib.sha256(bytes.fromhex(d)).hexdigest()
    checksum = e[:8]
    assert checksum == b[-8:]
    return f"{b}"


def decompress_xy(yx):
    is_even = yx[:2] == "02"
    x = int(yx[2:], 16)
    y = prime_mod_sqrt(x**3 + 7, P)
    if y[0] % 2 == 0 and is_even:
        return [x, y[0]]
    return [x, y[1]]


def compress_xy(xy):
    prefix = "02" if xy[1] % 2 == 0 else "03"
    key = f"{prefix}{__my_hex(xy[0])}"
    return key


def generate(pk=None):
    private_key = __generate_private_key() if pk is None else pk

    wif = __private_to_wif(__my_hex(private_key, signed=False))
    pub_xy = __double_and_add(G, private_key)

    prefix = "02" if pub_xy[1] % 2 == 0 else "03"
    pub_key = f"{prefix}{__my_hex(pub_xy[0])}"

    # else:
    #   pub_key = f"04{my_hex(pub_xy[0])}{my_hex(pub_xy[1])}"
    #   assert len(pub_key) == 130

    address = __get_public_key_address(f"{pub_key}")
    p2pkh = __get_P2PKH_script_address(
        f"76a9{str(address, 'UTF-8').encode().hex()}88ac"
    )

    return (
        f"{__my_hex(private_key, signed=False)}",
        wif,
        pub_key,
        str(address, "UTF-8"),
        f"3{str(p2pkh, 'UTF-8')}",
    )


def pub_from_prv(private_key, compressed=True):
    # assert len(__my_hex(private_key, signed=False)) == 64

    pub_xy = __double_and_add(G, private_key)
    x = pub_xy[0]
    y = pub_xy[1]

    if compressed:
        prefix = "02" if y % 2 == 0 else "03"
        return f"{prefix}{x.to_bytes(32, 'big').hex()}"

    return f"04{x.to_bytes(32, 'big').hex()}{y.to_bytes(32, 'big').hex()}"


def legendre_symbol(a, p):
    """
    Legendre symbol
    Define if a is a quadratic residue modulo odd prime
    http://en.wikipedia.org/wiki/Legendre_symbol
    """
    ls = pow(a, (p - 1) >> 1, p)
    if ls == p - 1:
        return -1
    return ls


def prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1) >> 2, p)
        return [x, p - x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q & 1 == 0:
        s += 1
        q >>= 1

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1) >> 1, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in xrange(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p - x]
