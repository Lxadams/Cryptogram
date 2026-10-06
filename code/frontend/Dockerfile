# Build-only image: compiles the Tauri desktop shell into a Linux bundle
# (.deb + AppImage). This is NOT meant to be `docker run` — Tauri needs a
# real display/webview to launch, so containers can't run the app itself.
# What a container *can* do reproducibly is provide the pinned Rust +
# webkit2gtk/GTK toolchain and produce the installer, e.g. in CI.
#
# Build context is `code/` (same as server/client):
#   docker build -f frontend/Dockerfile -t e2e-messenger-frontend-build .
#
# Extract the artifacts with buildx's local output instead of docker run:
#   docker buildx build -f frontend/Dockerfile --target artifacts \
#     --output type=local,dest=./frontend-bundle .
# -> ./frontend-bundle/{deb,appimage}/...
#
# Linux-only output: cross-compiling the Windows/macOS Tauri bundles isn't
# possible from a Linux container, so those still need native runners.

FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl wget file pkg-config \
    libwebkit2gtk-4.1-dev libxdo-dev libssl-dev \
    libayatana-appindicator3-dev librsvg2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown \
    && cargo install trunk --locked \
    && cargo install tauri-cli --version "^2" --locked

WORKDIR /app
COPY fec/Cargo.toml ./fec/
COPY fec/src ./fec/src
COPY cell/Cargo.toml ./cell/
COPY cell/src ./cell/src
COPY client/Cargo.toml client/Cargo.lock ./client/
COPY client/src ./client/src
COPY frontend/Cargo.toml frontend/Cargo.lock ./frontend/
COPY frontend/src ./frontend/src
COPY frontend/index.html frontend/style.css frontend/Trunk.toml ./frontend/
COPY frontend/src-tauri/Cargo.toml frontend/src-tauri/Cargo.lock ./frontend/src-tauri/
COPY frontend/src-tauri/build.rs frontend/src-tauri/tauri.conf.json ./frontend/src-tauri/
COPY frontend/src-tauri/src ./frontend/src-tauri/src
COPY frontend/src-tauri/icons ./frontend/src-tauri/icons
COPY frontend/src-tauri/capabilities ./frontend/src-tauri/capabilities

WORKDIR /app/frontend
# Limited to deb/appimage: the only Linux-buildable targets without a
# macOS/Windows toolchain (tauri.conf.json's `bundle.targets: "all"` would
# otherwise also attempt those and fail).
RUN cargo tauri build --bundles deb,appimage

FROM scratch AS artifacts
COPY --from=builder /app/frontend/src-tauri/target/release/bundle /bundle
