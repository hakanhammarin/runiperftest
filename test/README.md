# Tests

This directory contains the test suite for `runiperftest.sh`.

## Framework

Tests use [BATS (Bash Automated Testing Framework)](https://github.com/bats-core/bats-core).

### Install BATS

```bash
git clone https://github.com/bats-core/bats-core.git
cd bats-core && ./install.sh /usr/local
```

Or via package manager:

```bash
# Fedora/RHEL
dnf install bats

# Ubuntu/Debian
apt-get install bats
```

### Run tests

```bash
bats test/runiperftest.bats
```

## Coverage areas

| Area | Test cases |
|---|---|
| `vm.list` parsing | Valid entries, localhost, multiple entries, empty file |
| Log filename derivation | IP → filename, filename → IP (sed) |
| SUM line extraction | Normal output, no SUM, multiple SUM lines |
| Flow string formatting | Normal and localhost flows |
| Aggregate TP calculation | Single file, multiple files, no SUM lines |
| Log file counting | Single and multiple servers |
| Log cleanup | Removes `.log` files, preserves other files |
| Process wait loop | Off-by-one threshold regression tests |
