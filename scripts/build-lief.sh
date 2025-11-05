#!/bin/bash
set -e

# Build LIEF library with CMake before building the Node addon

BUILD_DIR="lief-build"
LIEF_SRC="LIEF"

echo "Building LIEF library..."

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure LIEF with CMake (minimal build for speed)
cmake "../$LIEF_SRC" \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
  -DLIEF_PYTHON_API=OFF \
  -DLIEF_RUST_API=OFF \
  -DLIEF_C_API=OFF \
  -DLIEF_OAT=OFF \
  -DLIEF_DEX=OFF \
  -DLIEF_VDEX=OFF \
  -DLIEF_ART=OFF \
  -DLIEF_ASM=OFF \
  -DLIEF_TESTS=OFF \
  -DLIEF_EXAMPLES=OFF \
  -DLIEF_DOC=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON

# Build LIEF
cmake --build . --config Release

cd ..

echo "LIEF build complete!"
