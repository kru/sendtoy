# Description

Send To Y is a local, peer-to-peer file transfer system optimized for cross-platform compatibility with zero configuration and no internet dependency.

## Features

- **Zero-Configuration:** Auto-discovery via local multicast (mDNS/UDP).
- **Direct P2P:** High-speed TCP transfers.
- **Secure:** Designed for end-to-end encryption (Monocypher).
- **Portable:** Pure C implementation with minimal dependencies.

## Building

This project uses the `nob.h` build system (Zero-dependency build).

### Prerequisites

- A C compiler (`gcc`, `clang`, or `cl.exe` for MSVC).
- Windows, Linux, or macOS.

### Steps

1. **Bootstrap the build system:**

   **Linux / macOS:**
   ```sh
   cc -o nob nob.c
   ```

   **Windows (MSVC Native Tools Command Prompt):**
   ```cmd
   cl nob.c
   ```

2. **Build the project:**

   ```sh
   ./nob
   ```
   (or `nob.exe` on Windows)

   This will create a `build/` directory containing the executable.

## Running

```sh
./build/sendtoy
```
