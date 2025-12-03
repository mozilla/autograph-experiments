# Post-Quantum Signature Verification Performance Test

Benchmark signature verification performance for post-quantum algorithms ML-DSA-65, Falcon-512 and current algorithms RSA-4096, ECDSA-384

## Download Release build

- (Link TBD)

---

## 1. Install Dependencies for your OS:

### Linux (Debian/Ubuntu)

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

## 2. Build and Run

### Linux and MacOS
```bash
cargo build --release
./target/release/post-quantum-client-testing
```

### Windows
```powershell
cargo build --release
.\target\release\post-quantum-client-testing.exe
```
