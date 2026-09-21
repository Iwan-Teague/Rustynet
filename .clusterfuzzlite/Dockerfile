# ClusterFuzzLite build image (AQ-29).
#
# base-builder-rust ships the pinned nightly toolchain plus cargo-fuzz, which
# the repo deliberately does NOT require locally (the compile-only
# fuzz_build_gate.sh runs on stable). The project name below must match the
# GitHub repository name (`rustynet`) because CFL copies the checkout to
# $SRC/<project_name> and invokes $SRC/build.sh with $OUT pointing at the
# fuzz-target output directory.
FROM gcr.io/oss-fuzz-base/base-builder-rust
COPY . $SRC/rustynet
WORKDIR $SRC/rustynet
COPY ./.clusterfuzzlite/build.sh $SRC/
