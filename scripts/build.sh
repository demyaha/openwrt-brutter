#!/bin/sh
# Builds the release files for common OpenWrt targets into dist/.
#   scripts/build.sh 0.1.0
set -eu

version=${1:?usage: scripts/build.sh VERSION}
cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist

build() { # name GOARCH [VAR=value ...]
	name=$1
	arch=$2
	shift 2
	env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$@" \
		go build -trimpath -ldflags "-s -w -X main.version=$version" -o "dist/brutter-linux-$name" .
}

build arm64 arm64
build armv7 arm GOARM=7
build armv5 arm GOARM=5
build mips mips GOMIPS=softfloat
build mipsle mipsle GOMIPS=softfloat
build amd64 amd64
build 386 386 GO386=softfloat
cp init.d/brutter dist/brutter.init

cd dist
if command -v sha256sum >/dev/null; then
	sha256sum brutter-linux-* brutter.init >SHA256SUMS
else
	shasum -a 256 brutter-linux-* brutter.init >SHA256SUMS
fi
ls -l
