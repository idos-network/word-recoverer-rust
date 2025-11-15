# Word Recoverer - BIP39 Seed Phrase Recovery Tool

A blazing fast command-line tool written in Rust for recovering missing BIP39 seed phrase words by matching against known Ethereum addresses.

## Features

- **Ultra-fast parallel processing** using Rayon
- **BIP39 checksum optimization** reduces search space by factor of 256
- **Auto-detects missing words** - no need to specify how many are missing
- **Auto-checks common derivation paths** - covers Ledger, Trezor, MetaMask patterns
- Supports recovering 1-3 missing words at the end of a seed phrase
- Multi-address and multi-derivation path support
- Progress tracking with real-time updates
- Early exit optimization when match is found
- Zero-copy operations for maximum performance

## Installation

### Build from source

```bash
cargo build --release
```

The binary will be available at `./target/release/word-recoverer`

## Usage

```bash
word-recoverer [OPTIONS] --phrase <PHRASE> --addresses <ADDRESSES>
```

### Options

- `-p, --phrase <PHRASE>` - Partial BIP39 seed phrase (missing words at the end)
- `-a, --addresses <ADDRESSES>` - File containing target addresses to check against (one per line)
- `-d, --derivations <DERIVATIONS>` - File containing derivation paths (optional, see defaults below)
- `-i, --indices <INDICES>` - Number of indices to check for each derivation path pattern (default: 10)
- `-t, --threads <THREADS>` - Number of threads to use (0 = all available cores)
- `-h, --help` - Print help information
- `-V, --version` - Print version information

### Default Derivation Paths

When no custom derivation file is provided, the tool automatically generates derivation paths based on the `--indices` parameter (default: 10):
- **Ledger Legacy** (Chrome app): `m/44'/60'/0'/i` where i = 0 to (indices-1)
- **BIP-44 Standard** (Trezor/MEW/MetaMask): `m/44'/60'/0'/0/i` where i = 0 to (indices-1)
- **Ledger Live**: `m/44'/60'/i'/0/0` where i = 0 to (indices-1)

By default, this generates 30 paths (10 indices × 3 patterns). You can customize this with the `--indices` flag:
- `--indices 1`: Generates 3 paths (checks only index 0 for each pattern)
- `--indices 20`: Generates 60 paths (checks indices 0-19 for each pattern)
- `--indices 100`: Generates 300 paths (checks indices 0-99 for each pattern)

### Example

```bash
# Create an addresses file
echo "0x6B3AfC1a634387f2694295bF6BA54bfE8700C6f3" > addresses.txt

# Run the recovery (auto-detects 2 missing words)
./target/release/word-recoverer \
  --phrase "tower wealth vanish kiwi truck junk reflect laugh shaft dumb delay wrist circle tip reflect shy pond canyon vivid develop arrest sibling" \
  --addresses addresses.txt
```

### Custom Derivation Paths

Create a file with derivation paths (one per line):
```
m/44'/60'/0'/0/0
m/44'/60'/0'/0/1
m/44'/60'/0'/0/2
```

Then use:
```bash
./target/release/word-recoverer \
  --phrase "your partial phrase here" \
  --addresses addresses.txt \
  --derivations paths.txt
```

## Performance

The tool uses several optimization techniques:
- **BIP39 checksum validation** to dramatically reduce search space
- **Parallel processing** with Rayon for multi-core utilization
- **Early exit** stops searching once a match is found
- **Optimized cryptographic operations** using proven Rust libraries

### Checksum Optimization

BIP39 24-word phrases contain 256 bits of entropy + 8 bits of checksum. This dramatically reduces the search space:
- **1 missing word**: Only 8 combinations (3 bits entropy) instead of 2,048
- **2 missing words**: Only 16,384 combinations (14 bits entropy) instead of 4,194,304 (256x reduction!)
- **3 missing words**: 33,554,432 combinations (25 bits entropy) instead of 8,589,934,592

### Benchmarks

For a 24-word seed phrase with 2 missing words:
- **Search space**: 16,384 combinations (vs 4.2 million without optimization)
- **Recovery time**: ~1-2 seconds on modern hardware
- Successfully recovered test phrase "foil hen" in 1.39 seconds (9,502 checks)

## Security Notes

⚠️ **WARNING**: This tool is designed for legitimate recovery of your own seed phrases only.

- Never use this tool with someone else's seed phrase
- Be aware that seed phrases give complete access to cryptocurrency wallets
- Always verify recovered phrases on a secure, offline machine before use
- Delete any files containing seed phrases or addresses after use

## Dependencies

- `bip39` - BIP39 mnemonic generation and validation
- `tiny-hderive` - HD wallet key derivation (BIP32)
- `secp256k1` - Elliptic curve cryptography
- `sha3` - Keccak256 hashing for Ethereum addresses
- `rayon` - Parallel processing
- `clap` - Command-line argument parsing

## License

MIT or Apache-2.0, at your option.

## Disclaimer

This tool is provided as-is for educational and recovery purposes. The authors are not responsible for any loss of funds or misuse of this software.
