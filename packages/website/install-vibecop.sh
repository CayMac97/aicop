#!/bin/sh
set -e

echo ""
echo " ========================================="
echo "  VibeCop - AI Code Scanner"
echo "  Installing via npm..."
echo " ========================================="
echo ""

if ! command -v node >/dev/null 2>&1; then
  echo " [ERROR] Node.js is not installed."
  echo " Please install Node.js first: https://nodejs.org"
  exit 1
fi

NODE_VER=$(node -v)
echo " Node.js found: $NODE_VER"
echo ""
echo " Installing vibecop globally..."
echo ""

npm install -g vibecop

echo ""
echo " ========================================="
echo "  VibeCop installed successfully!"
echo ""
echo "  Usage:"
echo "    cd your-project"
echo "    vibecop scan ./src"
echo " ========================================="
echo ""
