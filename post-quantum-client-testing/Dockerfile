FROM rust:1.90.0 AS build

# Install dependencies
RUN apt-get update && apt-get install -y \
    libclang-dev \
    cmake

# Set directory
WORKDIR /src

# Copy the project files and dependencies into container
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the executable
RUN cargo build --release
