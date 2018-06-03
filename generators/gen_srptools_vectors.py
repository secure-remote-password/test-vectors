# Generates SRP test vectors using srptools:
# https://github.com/idlesign/srptools
#
# Usage: python gen_srptools_vectors.py >srptools.json

from srptools import SRPContext, SRPServerSession, SRPClientSession
from srptools.utils import int_from_hex, hex_from
from srptools.constants import HASH_SHA_256
from srptools.constants import PRIME_1536_GEN, PRIME_1536
from srptools.constants import PRIME_2048_GEN, PRIME_2048
from srptools.constants import PRIME_3072_GEN, PRIME_3072
from srptools.constants import PRIME_4096_GEN, PRIME_4096
from srptools.constants import PRIME_6144_GEN, PRIME_6144

import hashlib
HASH_SHA_384 = hashlib.sha384
HASH_SHA_512 = hashlib.sha512

# initial values from RFC5054 test vector to use instead of random
username = 'alice'
password = 'password123'
static_salt = int_from_hex('BEB25379D1A8581EB5A727673A2441EE')
static_client_private = int_from_hex('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393')
static_server_private = int_from_hex('E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20')

def get_context(prime=None, generator=None, hash_func=None):
    return SRPContext(username, password, prime=prime, generator=generator, hash_func=hash_func)

def gen_test_vector(context, hash_name, size):

    # signing up: computing the private key and the verifier
    #context = SRPContext(username, password)
    prime = context.prime
    gen = context.generator
    multiplier = hex_from(context._mult)
    private_key = context.get_common_password_hash(static_salt)
    password_verifier = context.get_common_password_verifier(private_key)

    # ephemeral values
    client_public = context.get_client_public(static_client_private)
    server_public = context.get_server_public(password_verifier, static_server_private)
    common_secret = context.get_common_secret(server_public, client_public)

    # computing session keys
    server_premaster_secret = context.get_server_premaster_secret(
        password_verifier, static_server_private, client_public, common_secret)
    client_premaster_secret = context.get_client_premaster_secret(
        private_key, server_public, static_client_private, common_secret)
    assert client_premaster_secret == server_premaster_secret

    server_session_key = context.get_common_session_key(server_premaster_secret)
    client_session_key = context.get_common_session_key(client_premaster_secret)
    assert server_session_key == client_session_key

    client_session_key_proof = context.get_common_session_key_proof(
        client_session_key, static_salt, server_public, client_public)

    server_session_key_proof = context.get_common_session_key_proof_hash(
        server_session_key, client_session_key_proof, client_public)

    # output
    def hex_from_bytes(val):
        return hex_from(int_from_hex(hex_from(val)))

    return """{{
        "H": "{}",
        "size": {},

        "N": "{}",
        "g": "{}",
        "I": "{}",
        "P": "{}",
        "s": "{}",
        "k": "{}",
        "x": "{}",
        "v": "{}",
        "a": "{}",
        "b": "{}",
        "A": "{}",
        "B": "{}",
        "u": "{}",
        "S": "{}",
        "K": "{}",
        "M1": "{}",
        "M2": "{}"
    }}""".format(hash_name, size,
        prime, gen, username, password, hex_from(static_salt), multiplier,
        hex_from(private_key), hex_from(password_verifier),
        hex_from(static_client_private), hex_from(static_server_private),
        hex_from(client_public), hex_from(server_public), hex_from(common_secret),
        hex_from(server_premaster_secret), hex_from_bytes(server_session_key),
        hex_from_bytes(client_session_key_proof),
        hex_from_bytes(server_session_key_proof))


def gen_test_vectors(prime=None, gen=None, size=1024):

    context = get_context(prime=prime, generator=gen)
    json1 = gen_test_vector(context, "sha1", size)

    context = get_context(prime=prime, generator=gen, hash_func=HASH_SHA_256)
    json2 = gen_test_vector(context, "sha256", size)

    context = get_context(prime=prime, generator=gen, hash_func=HASH_SHA_384)
    json3 = gen_test_vector(context, "sha384", size)

    context = get_context(prime=prime, generator=gen, hash_func=HASH_SHA_512)
    json4 = gen_test_vector(context, "sha512", size)

    return json1, json2, json3, json4

# generate test vectors

s1024sha1, s1024sha256, s1024sha384, s1024sha512 = gen_test_vectors()
s1536sha1, s1536sha256, s1536sha384, s1536sha512 = gen_test_vectors(PRIME_1536, PRIME_1536_GEN, 1536)
s2048sha1, s2048sha256, s2048sha384, s2048sha512 = gen_test_vectors(PRIME_2048, PRIME_2048_GEN, 2048)
s3072sha1, s3072sha256, s3072sha384, s3072sha512 = gen_test_vectors(PRIME_3072, PRIME_3072_GEN, 3072)
s4096sha1, s4096sha256, s4096sha384, s4096sha512 = gen_test_vectors(PRIME_4096, PRIME_4096_GEN, 4096)
s6144sha1, s6144sha256, s6144sha384, s6144sha512 = gen_test_vectors(PRIME_6144, PRIME_6144_GEN, 6144)

# print json

json = """{{
    "comments": "Generated using srptools",
    "url": "https://github.com/idlesign/srptools",

    "testVectors": [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}]
}}""".format(
    s1024sha1, s1024sha256, s1024sha384, s1024sha512,
    s1536sha1, s1536sha256, s1536sha384, s1536sha512,
    s2048sha1, s2048sha256, s2048sha384, s2048sha512,
    s3072sha1, s3072sha256, s3072sha384, s3072sha512,
    s4096sha1, s4096sha256, s4096sha384, s4096sha512,
    s6144sha1, s6144sha256, s6144sha384, s6144sha512)

print(json)
