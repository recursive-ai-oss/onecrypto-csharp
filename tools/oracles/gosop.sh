#!/usr/bin/env bash
# Installs GopenPGP's sop driver (`gosop`) with `go install` at a pinned module version; the Go module proxy checks the module
# hash against the checksum database. The binary is only executed.
#   tools/oracles/gosop.sh [v1.1.0]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/go-sdk/bin:$PATH
VER=${1:-v1.1.0}
if [ ! -x "$ORACLES/gosop-$VER/gosop" ]; then
  GOBIN=$ORACLES/gosop-$VER GOFLAGS=-mod=mod GOPATH=$ORACLES/src/gopath go install github.com/ProtonMail/gosop@"$VER"
fi
"$ORACLES/gosop-$VER/gosop" version
