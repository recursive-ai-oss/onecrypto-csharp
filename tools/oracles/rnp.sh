#!/usr/bin/env bash
# Installs RNP (`rnp`, `rnpkeys`) from the distro packages, extracted user-locally, so it is only executed. Version is whatever the
# distribution carries (recorded in VERSION); RNP ships no sop driver.
#   tools/oracles/rnp.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dir=$ORACLES/rnp-distro
if [ ! -x "$dir/usr/bin/rnp" ]; then
  mkdir -p "$dir/dl"
  (cd "$dir/dl" && apt-get download rnp librnp0 libbotan-2-19 libjson-c5 libsexpp0 2>&1 | tail -3 || true)
  for d in "$dir"/dl/*.deb; do dpkg -x "$d" "$dir"; done
fi
export LD_LIBRARY_PATH=$dir/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
"$dir/usr/bin/rnp" --version | head -3 | tee "$dir/VERSION"
