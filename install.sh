#!/bin/sh
set -e

REPO="nelssec/qualys-agentless"
BINARY="qualys-k8s"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if [ "$OS" = "darwin" ]; then
    PLATFORM="darwin-${ARCH}"
elif [ "$OS" = "linux" ]; then
    PLATFORM="linux-${ARCH}"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

VERSION="${VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY}-${PLATFORM}"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}-${PLATFORM}"
fi

echo "Downloading ${BINARY} for ${PLATFORM}..."
curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${BINARY}"
chmod +x "/tmp/${BINARY}"

if [ -w "$INSTALL_DIR" ]; then
    mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Usage:"
echo "  ${BINARY} scan                    # Scan using ~/.kube/config"
echo "  ${BINARY} scan --provider aws     # Scan EKS cluster"
echo "  ${BINARY} scan --help             # Show all options"
