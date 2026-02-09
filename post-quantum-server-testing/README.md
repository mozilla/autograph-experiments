# Post-Quantum Signature Generation Performance Test

Benchmark signature generation performance for post-quantum algorithms ML-DSA-65, Falcon-512 and current algorithms RSA-4096, ECDSA-384.

This is to help us investigate and understand performance issues we might run into while doing code-signing and content-signing.

The test will execute 100 signature generations for 4 different algorithms each with 2 different payload sizes. Then return the signing time per operation of each algorithm.

## Running the Testing Program

### Requirements

This program is meant to be a server-side test and can only be tested by authenticated GCP users, otherwise KMS signing will not work. 

**Note:** The ML-DSA-65 and ECDSA-384 test functions use KMS key names `mldsa` and `ecdsa`. If your KMS keys have different names, you'll need to update the key names in the `SignData()` function calls in `main.go`.

### Linux (Ubuntu/Debian)

#### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y \
    git \
    cmake \
    build-essential \
    pkg-config \
    libssl-dev \
    golang-go
```

#### 2. Configure Environment Variables

Create a `.env` file in the `src` directory with your own Google KMS details:

```bash
LOCATION=global
KEYRING=your-keyring
PROJECT_ID=your-gcp-project-id
```

#### 3. Build and Install liboqs

```bash
# Clone and install the liboqs using cmake
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 4
sudo cmake --build liboqs/build --target install
```
**Note:** Change `--parallel 4` to the amount of available cores on your system.

#### 4. Set Up liboqs-go Wrapper

```bash
# Clone the liboqs-go
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-go

# Next, you must modify the following lines in $HOME/liboqs-go/.config/liboqs-go.pc
LIBOQS_INCLUDE_DIR=/usr/local/include
LIBOQS_LIB_DIR=/usr/local/lib

# Add these environment variables
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$PWD/liboqs-go/.config
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

**Note:** The `liboqs-go.pc` might already have the lines added

#### 5. Authenticate with GCP

```bash
gcloud auth application-default login
```

#### 6. Install Go Dependencies

```bash
cd post-quantum-server-testing/src
go mod download
```

#### 7. Run the Program

```bash
go run main.go
```
