# Post-Quantum Signature Verification Performance Test

Benchmark signature verification performance for post-quantum algorithms ML-DSA-65, Falcon-512 and current algorithms RSA-4096, ECDSA-384.

This is to help us investigate and understand performance issues internet users may run into as code-signing and content-signing processes make the switch to quantum resistant algorithms.

The test will execute 1000 signature verifications for 4 different algorithms and 2 different payload sizes. Then upload the results along with minimal information about the system (see example below).

## Running the latest release

Download the [latest release](https://github.com/mozilla/autograph-experiments/releases/latest) for your operating system and unzip the executable.

### Linux

Just run it in your terminal `./post-quantum-client-testing`.

### Windows

We did not setup an executable signing pipeline because this is a short experiment. Windows will (probably) warn you about this.

You can double click on the file to run it, select "More info" and "Run anyway" to run the file via explorer.

Or you can run via powershell like `.\post-quantum-client-testing.exe`. 
Note: Powershell _might_ fail silently due to windows blocking the unsigned binary. You can run `Set-ExecutionPolicy Unrestricted -Scope Process` and try again.

### MacOS

Since we did not setup a executable signing pipeline, MacOS will not let you run the binary.

To fix this, you can go into "Settings" then "Privacy & Security" and click "Run Anyway" to run the executable

Or you can run via terminal like `./post-quantum-client-testing`
Note: This will still require you to go into settings and allow the executable

## Building your own release

## 1. Install Dependencies for your OS:

### Linux (Debian/Ubuntu example)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```bash
# Install build dependencies
sudo apt update
sudo apt install -y build-essential pkg-config libclang-dev cmake libssl-dev
```

---

### MacOS

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

```bash
# Install OpenSSL using brew
brew install openssl@3

# If there are issues with OQS, then this may be needed
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_ROOT_DIR/lib/pkgconfig"
```

```bash
# Install cmake
brew install cmake
```

---

### Windows
1. **Install Rust**  
   Download from: https://rustup.rs/

2. **Visual Studio Build Tools**  
   Download from: https://visualstudio.microsoft.com/downloads/  
   Select "Desktop development with C++" during installation

3. **LLVM** (for libclang)  
   Download from: https://github.com/llvm/llvm-project/releases/latest  

4. **CMake**  
   Download from: https://cmake.org/download/  

5. **OpenSSL**  
   Download from: https://slproweb.com/products/Win32OpenSSL.html

---

### BSD

```bash
# Install rust, cmake, clang
pkg install rust cmake llvm
```

---

## 2. Build and Run

### Linux/MacOS/BSD
```bash
cargo build --release
./target/release/post-quantum-client-testing
```

### Windows
```powershell
cargo build --release
.\target\release\post-quantum-client-testing.exe
```

## Example data
Example data to show what information is collected. This is just to help us identify hardware or operating systems (or a combination of those) that need optimization.

```json
{
  "system_info": {
    "os": "Linux (Pop!_OS 24.04)",
    "total_memory": 65,
    "cpu_brand": "AMD Ryzen 5 7640U w/ Radeon 760M Graphics",
    "cpu_cores": 6
  },
  "test_results": [
    {
      "algorithm": "ML-DSA-65",
      "payload_size": "small",
      "iterations": 1000,
      "time_ms": 35.321318
    },
    {
      "algorithm": "Falcon-512",
      "payload_size": "small",
      "iterations": 1000,
      "time_ms": 27.723715
    },
    {
      "algorithm": "RSA-4096",
      "payload_size": "small",
      "iterations": 1000,
      "time_ms": 70.789864
    },
    {
      "algorithm": "ECDSA-384",
      "payload_size": "small",
      "iterations": 1000,
      "time_ms": 542.577442
    },
    {
      "algorithm": "ML-DSA-65",
      "payload_size": "medium",
      "iterations": 1000,
      "time_ms": 1325.534336
    },
    {
      "algorithm": "Falcon-512",
      "payload_size": "medium",
      "iterations": 1000,
      "time_ms": 1316.1723869999998
    },
    {
      "algorithm": "RSA-4096",
      "payload_size": "medium",
      "iterations": 1000,
      "time_ms": 1356.240576
    },
    {
      "algorithm": "ECDSA-384",
      "payload_size": "medium",
      "iterations": 1000,
      "time_ms": 2565.50272
    }
  ]
}
```
