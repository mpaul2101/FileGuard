# FileGuard CLI (C++17)

FileGuard is a multi-threaded C++17 CLI that recursively scans a directory, detects file type using magic bytes, computes SHA-256 hashes, and optionally exports a JSON report.

## Features

- Recursive directory scanning (`--path`)
- Multi-threaded processing (`--threads`)
- File type detection via magic bytes (PDF, PNG, JPEG, ZIP, PE EXE, ELF, UNKNOWN)
- SHA-256 streaming hashing (OpenSSL)
- Security-friendly anomaly flags:
  - extension mismatch
  - is executable
  - suspicious double extension
  - skipped size
  - read error
- Console summary + optional JSON report (`--json`)

## Build

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

## Run

```bash
./fileguard --path ../samples --threads 8 --json report.json
```

## Bootstrap (Ubuntu/Debian)

Use one command to install dependencies, build, and run:

```bash
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh --path /tmp --threads 4 --max-size 50 --json build/report.json
```

Skip dependency installation if you already installed tools:

```bash
./scripts/bootstrap.sh --no-install --path /tmp
```

Optional flags:

- `--max-size <MB>` skip files larger than MB
- `--follow-symlinks` follow directory symlinks

## Example

```bash
./fileguard --path /tmp --threads 4 --max-size 50 --json report.json
```
