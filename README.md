# Motoko DID

[![MOPS](https://img.shields.io/badge/MOPS-did-blue)](https://mops.one/did)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/edjcase/motoko_did/blob/main/LICENSE)

A comprehensive Motoko implementation for working with Decentralized Identifiers (DIDs) supporting multiple DID methods including did:key, did:plc, and did:web.

## Package

### MOPS

```bash
mops add did
```

To set up MOPS package manager, follow the instructions from the [MOPS Site](https://mops.one)

## What are DIDs?

Decentralized Identifiers (DIDs) are a type of identifier that enables verifiable, decentralized digital identity. A DID refers to any subject (e.g., a person, organization, thing, data model, abstract entity, etc.) as determined by the controller of the DID. Unlike typical, federated identifiers, DIDs have been designed so that they may be decoupled from centralized registries, identity providers, and certificate authorities.

This library supports three DID methods:

- **did:key** - Cryptographic key-based identifiers that encode public keys directly
- **did:plc** - Public Ledger of Credentials identifiers used in AT Protocol
- **did:web** - Web-based identifiers that resolve to DID documents over HTTPS

## Quick Start

### Example 1: Working with did:key

```motoko
import DID "mo:did";
import Debug "mo:core/Debug";

// Create a did:key from public key bytes
let publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
let didKey : DID.DID = #key({
  keyType = #ed25519;
  publicKey = publicKey;
});

// Convert to text representation
let text = DID.toText(didKey);
Debug.print(text); // "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
```

### Example 2: Working with did:plc

```motoko
import DID "mo:did";

// Create a did:plc identifier
let didPLC : DID.DID = #plc({
  identifier = "yk4dd2qkboz2yv6tpubpc6co";
});

// Convert to text representation
let text = DID.toText(didPLC);
// Returns: "did:plc:yk4dd2qkboz2yv6tpubpc6co"
```

### Example 3: Working with did:web

```motoko
import DID "mo:did";
import Domain "mo:url-kit/Domain";

// Create a did:web identifier
let domain = switch (Domain.fromText("example.com")) {
  case (#ok(domain)) domain;
  case (#err(e)) Debug.trap("Invalid domain: " # e);
};

let didWeb : DID.DID = #web({
  host = #domain(domain);
  port = null;
  path = ["users", "alice"];
});

// Convert to text representation
let text = DID.toText(didWeb);
// Returns: "did:web:example.com:users:alice"
```

### Example 4: Parsing DIDs from Text

```motoko
import DID "mo:did";

// Parse any supported DID method
let examples = [
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "did:plc:yk4dd2qkboz2yv6tpubpc6co",
  "did:web:example.com:users:alice"
];

for (didText in examples.vals()) {
  switch (DID.fromText(didText)) {
    case (#ok(did)) {
      Debug.print("Successfully parsed: " # DID.toText(did));
    };
    case (#err(error)) {
      Debug.print("Failed to parse: " # error);
    };
  };
};
```

## API Reference

### Main Types

```motoko
// Main DID type supporting multiple methods
public type DID = {
  #key : Key.DID;
  #plc : Plc.DID;
  #web : Web.DID;
};

// did:key specific types
public type Key.DID = {
  keyType : KeyType;
  publicKey : Blob;
};

public type KeyType = { #ed25519; #secp256k1; #p256 };

// did:plc specific types
public type Plc.DID = {
  identifier : Text;
};

// did:web specific types
public type Web.DID = {
  host : Host;
  port : ?Nat16;
  path : [Text];
};
```

### Core Functions

```motoko
// Convert any DID to text representation
public func toText(did : DID) : Text;

// Parse text to DID (auto-detects method)
public func fromText(text : Text) : Result.Result<DID, Text>;

// Check if two DIDs are equal
public func equal(did1 : DID, did2 : DID) : Bool;
```

### did:key Functions

```motoko
// Convert did:key to text with specified multibase encoding
public func Key.toText(did : Key.DID, multibase : MultiBase.MultiBase) : Text;

// Parse did:key from text
public func Key.fromText(text : Text) : Result.Result<Key.DID, Text>;

// Create did:key from raw public key
public func Key.fromPublicKey(keyType : KeyType, publicKey : Blob) : Result.Result<Key.DID, Text>;

// Check equality
public func Key.equal(did1 : Key.DID, did2 : Key.DID) : Bool;
```

### did:plc Functions

```motoko
// Convert did:plc to text
public func Plc.toText(did : Plc.DID) : Text;

// Parse did:plc from text
public func Plc.fromText(text : Text) : Result.Result<Plc.DID, Text>;

// Check equality
public func Plc.equal(did1 : Plc.DID, did2 : Plc.DID) : Bool;
```

### did:web Functions

```motoko
// Convert did:web to text
public func Web.toText(did : Web.DID) : Text;

// Parse did:web from text
public func Web.fromText(text : Text) : Result.Result<Web.DID, Text>;

// Create did:web from domain and path
public func Web.fromDomainAndPath(domain : Text, path : [Text]) : Result.Result<Web.DID, Text>;

// Get HTTPS URL for DID document resolution
public func Web.toHttpsUrl(did : Web.DID) : Text;

// Check equality
public func Web.equal(did1 : Web.DID, did2 : Web.DID) : Bool;
```

## Supported Key Types

### did:key

- **ed25519** - Most common elliptic curve signature system (32 bytes)
- **secp256k1** - Bitcoin-style elliptic curve (33 bytes compressed)
- **p256** - NIST P-256 elliptic curve (33 bytes compressed)

## DID Method Specifications

This implementation follows the official DID specifications:

### did:key

- [W3C DID Key Method Specification](https://w3c-ccg.github.io/did-method-key/)
- Uses multicodec for key type encoding and multibase (base58btc) for text representation

### did:plc

- [AT Protocol PLC Method](https://web.plc.directory/)
- Used primarily in the AT Protocol ecosystem for decentralized social networking

### did:web

- [W3C DID Web Method Specification](https://w3c-ccg.github.io/did-method-web/)
- Resolves DID documents over HTTPS at `/.well-known/did.json`

## Dependencies

This library depends on:

- `mo:core` - Core Motoko utilities
- `mo:multiformats` - Multicodec and multibase encoding
- `mo:url-kit` - URL and domain parsing utilities

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
