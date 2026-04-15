# GNUZero — Setup & Usage Guide

This guide walks a first-time user through setting up the GNUZero GCC plugin and running it against the Juliet test suite on a fresh Ubuntu system.

---


## Link to artifacts by the author  

https://zenodo.org/records/14277842 

## Prerequisites

- Ubuntu 22.04 or 24.04 (Noble)
- `sudo` access
- The GNUZero repository cloned to your machine, including:
  - `gcc_fork/` — patched GCC 13 source -- not included in this repo (due to large size), please refer to author shared repo
  - `gnuzero/` — the GCC plugin source
  - `juliet-testsuite-adapted/` — adapted Juliet C test cases

This guide assumes your working root is:
```
<your_customer_path>/GNUZero/gnuzero_artifacts/
```

Replace `<username>` with your actual username throughout.

---

## Step 1 — Install System Dependencies

```bash
sudo apt update
sudo apt install build-essential flex bison \
                 libgmp-dev libmpfr-dev libmpc-dev \
                 cmake ninja-build libwine-dev
```

| Package | Purpose |
|---|---|
| `build-essential` | gcc, g++, make |
| `flex`, `bison` | lexer/parser tools needed by GCC build |
| `libgmp-dev`, `libmpfr-dev`, `libmpc-dev` | math libraries required by GCC |
| `cmake`, `ninja-build` | build system for the plugin |
| `libwine-dev` | Windows API headers for compiling Juliet w32 test cases |

---

## Step 2 — Build the Custom GCC

This builds a patched GCC 13.0.1 from source and installs it to `~/.local`. This step takes **1–2 hours**.

```bash
cd <your_customer_path>/GNUZero/gnuzero_artifacts/gcc_fork

mkdir build && cd build

../configure \
  --prefix=/home/<username>/.local \
  --enable-languages=c,c++ \
  --disable-multilib \
  --enable-checking=yes,types,extra

make -j$(nproc)
make install
```

Verify the install:

```bash
/home/<username>/.local/bin/gcc --version
```

Expected output:
```
gcc (GCC) 13.0.1_custom 20230321 (experimental)
```

---

## Step 3 — Build the GNUZero Plugin

```bash
cd <your_customer_path>/GNUZero/gnuzero_artifacts/gnuzero

mkdir build && cd build

cmake -B . -S .. \
  -DCMAKE_C_COMPILER=/home/<username>/.local/bin/gcc \
  -DCMAKE_CXX_COMPILER=/home/<username>/.local/bin/g++ \
  -DGCC_VERSION=13.0.1_custom

make VERBOSE=1
```

On success, this produces:
```
gnuzero/build/libscrub.so
```

---

## Step 4 — Fix the scrub.h Symlink

The Juliet test case support directory contains a symlink to `scrub.h`. Make sure it points to the correct file:

```bash
ln -sf <your_customer_path>/GNUZero/gnuzero_artifacts/gnuzero/scrub.h \
  <your_customer_path>/GNUZero/gnuzero_artifacts/juliet-testsuite-adapted/testcasesupport/scrub.h
```

Verify:

```bash
ls -la <your_customer_path>/GNUZero/gnuzero_artifacts/juliet-testsuite-adapted/testcasesupport/scrub.h
```

---

## Step 5 — Run the Analysis

```bash
cd <your_customer_path>/GNUZero/gnuzero_artifacts/juliet-testsuite-adapted

python3 run_scrub_analysis.py run \
  -p <your_customer_path>/GNUZero/gnuzero_artifacts/gnuzero/build/libscrub.so \
  -id 226
```

### Available options

| Flag | Description |
|---|---|
| `-p`, `--plugin` | Path to `libscrub.so` (required) |
| `-id`, `--cweid` | CWE ID to test: `226` or `244` (default: `244`) |
| `-s`, `--sarif` | Output results in SARIF format |
| `-i`, `--interactive` | Confirm each test file before running |
| `--omit-good` | Skip good (non-vulnerable) test cases |
| `--omit-bad` | Skip bad (vulnerable) test cases |
| `-e`, `--explosion-factor` | Analyzer BB explosion factor (default: `5`) |

### Example — run CWE-244 with SARIF output

```bash
python3 run_scrub_analysis.py run \
  -p <your_customer_path>/GNUZero/gnuzero_artifacts/gnuzero/build/libscrub.so \
  -id 244 \
  --sarif
```

---

## How It Works

GNUZero is a **GCC plugin** that extends GCC's built-in `-fanalyzer` static analysis pass. When you compile a C file with `-fplugin=libscrub.so`, the plugin hooks into the analysis and checks for additional vulnerability patterns — such as sensitive data left uncleared in memory (CWE-226) or uncleared stack variables (CWE-244).

The Juliet test suite provides standardized C test cases with known-good and known-bad variants, allowing you to measure the plugin's detection accuracy.

```
gcc -fplugin=libscrub.so -fanalyzer -c file.c
         │
         └── GCC analyzer pass
                  │
                  └── libscrub.so hooks in → reports findings
```

---

## Troubleshooting

**`Please install wine on your system`**
Wine headers are missing. Run:
```bash
sudo apt install libwine-dev
ls /usr/include/wine/wine/windows   # should list headers
```

**`scrub.h: No such file or directory`**
The symlink in `testcasesupport/` is broken. Redo Step 4.

**`Plugin path issue`**
The path passed to `-p` does not exist. Verify `libscrub.so` was built in Step 3:
```bash
ls <your_customer_path>/GNUZero/gnuzero_artifacts/gnuzero/build/libscrub.so
```

**GCC build fails with missing library**
Make sure all deps from Step 1 are installed, then re-run `../configure`.

---

## Directory Structure

```
gnuzero_artifacts/
├── gcc_fork/                  # Patched GCC 13 source
│   └── build/                 # GCC build directory
├── gnuzero/                   # GCC plugin source
│   ├── src/                   # Plugin C++ source files
│   ├── inc/                   # Plugin headers
│   ├── scrub.h                # Main plugin header
│   └── build/                 # Plugin build output (libscrub.so)
└── juliet-testsuite-adapted/  # Juliet test suite
    ├── testcases/             # C test case files (CWE-226, CWE-244)
    ├── testcasesupport/       # Shared headers (std_testcase.h, scrub.h)
    ├── py_common.py           # Shared Python utilities
    └── run_scrub_analysis.py  # Main test runner script
```
