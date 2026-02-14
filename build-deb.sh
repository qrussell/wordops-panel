#!/bin/bash
set -e

# 1. Get Version from Argument (Default to 1.0-1 if not provided)
VERSION="${1:-1.0-1}"
PKG_NAME="wordops-panel"
SOURCE_DIR="wordops-panel"
OUTPUT_DEB="${PKG_NAME}_${VERSION}_all.deb"

echo "---------------------------------------------------------"
echo ">>> Building ${PKG_NAME} version: ${VERSION}"
echo "---------------------------------------------------------"

# 2. Update the Version in DEBIAN/control
# We use sed to find the line starting with "Version:" and replace it
if [ -f "${SOURCE_DIR}/DEBIAN/control" ]; then
    sed -i "s/^Version:.*/Version: ${VERSION}/" "${SOURCE_DIR}/DEBIAN/control"
    echo "Updated control file with version ${VERSION}"
else
    echo "Error: ${SOURCE_DIR}/DEBIAN/control not found!"
    exit 1
fi

# 3. Set Permissions (Crucial for Debian packages)
echo "Setting permissions..."
chmod 755 "${SOURCE_DIR}/DEBIAN/postinst"
chmod 755 "${SOURCE_DIR}/DEBIAN/prerm"
chmod -R 755 "${SOURCE_DIR}/opt/wordops-panel"

# 4. Clean previous builds of this specific version
rm -f "${OUTPUT_DEB}"

# 5. Build the Package
echo "Building .deb package..."
dpkg-deb --build "${SOURCE_DIR}" "${OUTPUT_DEB}"

echo "---------------------------------------------------------"
echo "Build Complete!"
echo "Package: ./${OUTPUT_DEB}"
echo "---------------------------------------------------------"