# tools

Scripts that fetch and pin oracle binaries, vector suites and corpora, and generators for test fixtures. Large downloads go to a cache outside the checkout and are never committed.

`extract-autocrypt-vectors.py <level1.html>` extracts the examples of the Autocrypt Level 1 specification (header, setup message and code, secret key, gossip message) into `testdata/openpgp/autocrypt/`.
