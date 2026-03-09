#!/bin/bash
set -ex

dnf install openssl-devel openssl-libs -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv venv --python /opt/python/cp314-cp314/bin/python3.14 /opt/venv
source /opt/venv/bin/activate
uv pip install --upgrade "maturin>=1,<2"
cd /io/

# Build into a clean dist/ directory to avoid stale wheel artifacts
rm -rf dist/
maturin build --release --strip --manylinux --sdist --out dist/
