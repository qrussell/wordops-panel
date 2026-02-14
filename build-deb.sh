#!/bin/bash

# -----------------------------------------
# WordOps Panel Debian Package Builder
# -----------------------------------------
# Usage:
#   ./build-deb.sh 1.0-1
#
# If no version is passed, defaults to 1.0-1
# Architecture is read from DEBIAN/control
# -----------------------------------------

VERSION="${1:-1.0-1}"
PKG_NAME="wordops-panel"

BUILD_ROOT="build"
PKG_DIR="${BUILD_ROOT}/${PKG_NAME}_${VERSION}"

echo "-----------------------------------------"
echo "Building ${PKG_NAME} version ${VERSION}"
echo "-----------------------------------------"

# Clean previous build
rm -rf "${BUILD_ROOT}"
mkdir -p "${PKG_DIR}"

# -----------------------------------------
# Create directory structure
# -----------------------------------------
mkdir -p "${PKG_DIR}/opt/${PKG_NAME}"
mkdir -p "${PKG_DIR}/etc/systemd/system"
mkdir -p "${PKG_DIR}/DEBIAN"

# -----------------------------------------
# Copy application files
# -----------------------------------------
rsync -av --exclude 'build' --exclude '.git' ./ "${PKG_DIR}/opt/${PKG_NAME}/"

# -----------------------------------------
# Copy maintainer scripts if they exist
# -----------------------------------------
if [[ -f "./DEBIAN/postinst" ]]; then
    echo "Including postinst script"
    cp ./DEBIAN/postinst "${PKG_DIR}/DEBIAN/postinst"
    chmod 755 "${PKG_DIR}/DEBIAN/postinst"
fi

if [[ -f "./DEBIAN/prerm" ]]; then
    echo "Including prerm script"
    cp ./DEBIAN/prerm "${PKG_DIR}/DEBIAN/prerm"
    chmod 755 "${PKG_DIR}/DEBIAN/prerm"
fi

# -----------------------------------------
# Create systemd service
# -----------------------------------------
cat <<EOF > "${PKG_DIR}/etc/systemd/system/wordops-panel.service"
[Unit]
Description=WordOps Panel (FastAPI)
After=network.target

[Service]
WorkingDirectory=/opt/wordops-panel
ExecStart=/usr/bin/python3 /opt/wordops-panel/main.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------------------
# Create DEBIAN/control
# -----------------------------------------
cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: web
Priority: optional
Architecture: $(dpkg --print-architecture)
Maintainer: Quentin Russell
Description: WordOps Panel - FastAPI-based management UI for WordOps servers.
EOF

# -----------------------------------------
# Read architecture from control file
# -----------------------------------------
ARCH=$(grep -i '^Architecture:' "${PKG_DIR}/DEBIAN/control" | awk '{print $2}')

echo "Detected architecture from control file: ${ARCH}"

# -----------------------------------------
# Permissions
# -----------------------------------------
chmod 755 "${PKG_DIR}/DEBIAN"
chmod 644 "${PKG_DIR}/etc/systemd/system/wordops-panel.service"

# -----------------------------------------
# Build the .deb package
# -----------------------------------------
FINAL_DEB="${PKG_NAME}_${VERSION}_${ARCH}.deb"

dpkg-deb --build "${PKG_DIR}" "${FINAL_DEB}"

echo ""
echo "-----------------------------------------"
echo "Package built successfully:"
echo "  ${FINAL_DEB}"
echo ""
echo "Install with:"
echo "  sudo dpkg -i ${FINAL_DEB}"
echo "-----------------------------------------"
