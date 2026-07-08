# Prison-Realm

Prison-Realm is a lightweight C++ DNS sinkhole server that blocks known ad/tracker domains using a local blocklist.

## Key Points

- Runs a UDP DNS server on port `53`
- Loads block rules from `data/blocklist.txt`
- Uses a reverse trie for fast blocklist lookups
- Returns sinkhole responses (`0.0.0.0` for A, `::` for AAAA) for blocked domains
- Forwards allowed queries to `8.8.8.8`
- Caches upstream responses with a thread-safe LRU cache
- Uses `epoll` + detached worker threads for concurrent traffic handling

## Requirements

- Linux environment
- `g++` with C++17 support
- `make`
- Permission to bind to port 53 (run with `sudo` or change the port in `src/main.cpp`)

## Build

```bash
make
```

The binary is created at:

```bash
build/dns_server
```

## Run

```bash
sudo ./build/dns_server
```

## Clean Build Files

```bash
make clean
```