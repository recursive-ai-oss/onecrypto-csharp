# Browser suite fixtures

Written by `tools/gen-browser-fixtures.sh` with the OpenSSL and OpenSSH recorded in `VERSION` and a throwaway CA. Every key here is a test key
generated for these files and protects nothing; the passphrase of the protected files is `password`. Regenerating replaces all of them
together (the suite only needs them to agree with each other).
