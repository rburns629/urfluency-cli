#!/bin/sh
# Builds one release archive: scripts/build-release.sh VERSION OUTDIR
# PACKAGE is what to build, ./cmd/urfluency (the community engine) unless set;
# the release sets it to the private engine's build, linked by a go.work.
# EXPECT_ENGINE, when set, is checked against urfluency version.
# On macOS it builds for the host architecture, or for GOARCH when set: Apple's
# clang targets both, so an Intel Mac builds the Apple silicon binary too. For
# Linux it builds a
# fully static binary inside the pinned Go Alpine image, so the result runs on any
# distribution regardless of its C library. Alpine keeps only the latest build of
# each package, so build-base cannot be pinned; the build log records the
# versions installed. BUILD_OS=Linux forces the Linux build
# on another host with Docker, for local testing.
set -eu
version=$1
out=$2
# The pinned image is in scripts/release/Dockerfile, where Dependabot sees it.
image=$(sed -n 's/^FROM //p' "$(dirname "$0")/release/Dockerfile")
ldflags="-s -w -X github.com/roburns/urfluency-cli/internal/cli.Version=$version"
pkg=${PACKAGE:-./cmd/urfluency}
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case "${BUILD_OS:-$(uname -s)}" in
Darwin)
  goos=darwin
  goarch=${GOARCH:-$(go env GOHOSTARCH)}
  # Run on macOS 13 and later, the oldest the Go toolchain targets, not only the
  # build runner's release.
  MACOSX_DEPLOYMENT_TARGET=13.0 CGO_ENABLED=1 GOARCH=$goarch go build -trimpath -ldflags "$ldflags" -o "$work/urfluency" "$pkg"
  ;;
Linux)
  goos=linux
  goarch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
  docker run --rm -v "$PWD":/src -v "$work":/out -w /src -e CGO_ENABLED=1 -e GOFLAGS=-buildvcs=false "$image" \
    sh -c "apk add --no-cache build-base >/dev/null && apk list --installed build-base gcc musl-dev binutils && go build -trimpath -ldflags '$ldflags -linkmode external -extldflags -static' -o /out/urfluency $pkg"
  ;;
*)
  echo "unsupported build host: $(uname -s)" >&2
  exit 1
  ;;
esac

if [ "$goos" = darwin ] && [ "$goarch" != "$(go env GOHOSTARCH)" ]; then
  # Built for the other Mac architecture, so it can't run here. Check instead
  # that it is that architecture, that an Apple silicon binary carries the
  # signature macOS requires to run it, and, for EXPECT_ENGINE, that its build
  # information names the engine's main package (the official build's) or the
  # CLI's (the community build's).
  want=$(echo "$goarch" | sed 's/amd64/x86_64/') # lipo's name for it
  if [ "$(lipo -archs "$work/urfluency")" != "$want" ]; then
    echo "built $(lipo -archs "$work/urfluency"), want $want" >&2
    exit 1
  fi
  if [ "$goarch" = arm64 ]; then
    codesign --verify "$work/urfluency"
  fi
  if [ -n "${EXPECT_ENGINE:-}" ]; then
    case "$EXPECT_ENGINE" in
    official) main=github.com/roburns/urfluency-engine/cmd/urfluency ;;
    *) main=github.com/roburns/urfluency-cli/cmd/urfluency ;;
    esac
    if ! go version -m "$work/urfluency" | grep -q "^[[:space:]]*path[[:space:]]*$main\$"; then
      echo "built $(go version -m "$work/urfluency" | sed -n 's/^[[:space:]]*path[[:space:]]*//p'), want $main for the $EXPECT_ENGINE engine" >&2
      exit 1
    fi
    echo "built $goos/$goarch with the $EXPECT_ENGINE engine ($main)"
  fi
elif [ -n "${EXPECT_ENGINE:-}" ]; then
  got=$("$work/urfluency" version)
  case "$got" in
  *"($EXPECT_ENGINE"*" engine)"*) echo "$got" ;;
  *)
    echo "built $got, want the $EXPECT_ENGINE engine" >&2
    exit 1
    ;;
  esac
fi
cp LICENSE.md README.md "$work/"
archive="urfluency_${version}_${goos}_${goarch}.tar.gz"
tar -C "$work" -czf "$out/$archive" urfluency LICENSE.md README.md
echo "$out/$archive"
