#!/usr/bin/env python3
"""Drives an OpenSSL libcrypto as a black-box AEAD oracle for the interop tests.

OpenSSL's command line cannot run AEAD modes such as OCB, so this talks to the shared library through its documented EVP and
OSSL_PARAM interfaces using ctypes. No OpenSSL source or header is read.

Usage: OPENSSL_LIBCRYPTO=/path/to/libcrypto.so.3 openssl_aead.py < requests.jsonl > responses.jsonl
Request (one JSON object per line, all binary values hex):
  {"op": "enc"|"dec", "cipher": "AES-128-OCB", "key": ..., "iv": ..., "aad": ..., "taglen": 16, "data": ..., "tag": ... (dec only)}
Response: {"ok": true, "data": ..., "tag": ...} or {"ok": false, "error": ...}; a failed tag check is {"ok": false}.
"""
import ctypes
import json
import os
import sys

lib = ctypes.CDLL(os.environ["OPENSSL_LIBCRYPTO"])


class OSSLParam(ctypes.Structure):
    # The five fields documented in OSSL_PARAM(3).
    _fields_ = [
        ("key", ctypes.c_char_p),
        ("data_type", ctypes.c_uint),
        ("data", ctypes.c_void_p),
        ("data_size", ctypes.c_size_t),
        ("return_size", ctypes.c_size_t),
    ]


vp = ctypes.c_void_p
lib.EVP_CIPHER_fetch.restype = vp
lib.EVP_CIPHER_fetch.argtypes = [vp, ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_CIPHER_CTX_new.restype = vp
lib.EVP_CIPHER_CTX_free.argtypes = [vp]
lib.EVP_CipherInit_ex2.argtypes = [vp, vp, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, vp]
lib.EVP_CipherUpdate.argtypes = [vp, vp, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
lib.EVP_CipherFinal_ex.argtypes = [vp, vp, ctypes.POINTER(ctypes.c_int)]
lib.EVP_CIPHER_CTX_set_params.argtypes = [vp, vp]
lib.EVP_CIPHER_CTX_get_params.argtypes = [vp, vp]
lib.OSSL_PARAM_construct_size_t.restype = OSSLParam
lib.OSSL_PARAM_construct_size_t.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
lib.OSSL_PARAM_construct_octet_string.restype = OSSLParam
lib.OSSL_PARAM_construct_octet_string.argtypes = [ctypes.c_char_p, vp, ctypes.c_size_t]
lib.OSSL_PARAM_construct_end.restype = OSSLParam


def params(*items):
    arr = (OSSLParam * (len(items) + 1))(*items, lib.OSSL_PARAM_construct_end())
    return arr


def run(req):
    cipher = lib.EVP_CIPHER_fetch(None, req["cipher"].encode(), None)
    if not cipher:
        return {"ok": False, "error": "cipher not available"}
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        enc = 1 if req["op"] == "enc" else 0
        key, iv, aad, data = (bytes.fromhex(req[k]) for k in ("key", "iv", "aad", "data"))
        ivlen = ctypes.c_size_t(len(iv))
        tag_in = bytes.fromhex(req["tag"]) if not enc else b""
        tag_buf = ctypes.create_string_buffer(req["taglen"])
        # OCB takes its tag length from a "tag" parameter with no data, set before the key and nonce.
        first = params(lib.OSSL_PARAM_construct_size_t(b"ivlen", ctypes.byref(ivlen)),
                       lib.OSSL_PARAM_construct_octet_string(b"tag", None, req["taglen"]))
        if lib.EVP_CipherInit_ex2(ctx, cipher, None, None, enc, first) != 1:
            return {"ok": False, "error": "init failed"}
        if lib.EVP_CipherInit_ex2(ctx, None, key, iv, enc, None) != 1:
            return {"ok": False, "error": "key/iv failed"}
        outl = ctypes.c_int(0)
        if aad and lib.EVP_CipherUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1:
            return {"ok": False, "error": "aad failed"}
        out = ctypes.create_string_buffer(len(data) + 32)
        total = 0
        if lib.EVP_CipherUpdate(ctx, out, ctypes.byref(outl), data, len(data)) != 1:
            return {"ok": False, "error": "update failed"}
        total = outl.value
        if not enc:
            tb = ctypes.create_string_buffer(tag_in, len(tag_in))
            p = params(lib.OSSL_PARAM_construct_octet_string(b"tag", tb, len(tag_in)))
            if lib.EVP_CIPHER_CTX_set_params(ctx, p) != 1:
                return {"ok": False, "error": "set tag failed"}
        fin = ctypes.create_string_buffer(32)
        if lib.EVP_CipherFinal_ex(ctx, fin, ctypes.byref(outl)) != 1:
            return {"ok": False}
        result = {"ok": True, "data": (out.raw[:total] + fin.raw[:outl.value]).hex()}
        if enc:
            p = params(lib.OSSL_PARAM_construct_octet_string(b"tag", tag_buf, req["taglen"]))
            if lib.EVP_CIPHER_CTX_get_params(ctx, p) != 1:
                return {"ok": False, "error": "get tag failed"}
            result["tag"] = tag_buf.raw.hex()
        return result
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


for line in sys.stdin:
    line = line.strip()
    if line:
        print(json.dumps(run(json.loads(line))), flush=True)
