#!/bin/sh
# Builds the release archives into dist/ for the version given (v1.2.3).
# Run by .github/workflows/release.yml; works locally too.
set -eu

version="${1:?usage: build-release.sh vX.Y.Z}"
rm -rf dist
mkdir -p dist

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os="${target%/*}"
  arch="${target#*/}"
  stage="dist/stage"
  rm -rf "$stage"
  mkdir -p "$stage"
  bin="brioly"
  [ "$os" = "windows" ] && bin="brioly.exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version#v}" -o "$stage/$bin" ./cmd/brioly
  cp LICENSE NOTICE README.md "$stage/"
  if [ "$os" = "windows" ]; then
    (cd "$stage" && zip -q "../brioly_${os}_${arch}.zip" ./*)
  else
    tar -C "$stage" -czf "dist/brioly_${os}_${arch}.tar.gz" .
  fi
done
rm -rf dist/stage

# install.sh checks a download against this file.
(cd dist && sha256sum brioly_* > checksums.txt)
ls -l dist
