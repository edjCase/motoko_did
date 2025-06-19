import Result "mo:new-base/Result";
import Nat "mo:new-base/Nat";
import Iter "mo:new-base/Iter";
import Blob "mo:new-base/Blob";
import Runtime "mo:new-base/Runtime";
import Text "mo:new-base/Text";
import Nat8 "mo:new-base/Nat8";
import Array "mo:new-base/Array";
import Buffer "mo:base/Buffer";
import BaseX "mo:base-x-encoder";
import VarInt "VarInt";

module {

    /// Represents the cryptographic key type used in a did:key identifier.
    ///
    /// ```motoko
    /// let keyType : KeyType = #ed25519; // Most common, 32 bytes
    /// let secpType : KeyType = #secp256k1; // Bitcoin-style, 33 bytes compressed
    /// let p256Type : KeyType = #p256; // NIST P-256, 33 bytes compressed
    /// ```
    public type KeyType = { #ed25519; #secp256k1; #p256 };

    /// Represents a did:key identifier with key type and public key bytes.
    ///
    /// ```motoko
    /// let didKey : DID = {
    ///   keyType = #ed25519;
    ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
    /// };
    /// ```
    public type DID = {
        keyType : KeyType;
        publicKey : Blob;
    };

    /// Converts a did:key to its text representation using base58btc encoding.
    ///
    /// ```motoko
    /// let didKey : DID = {
    ///   keyType = #ed25519;
    ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
    /// };
    /// let text = Key.toText(didKey);
    /// // Returns: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    /// ```
    public func toText(did : DID) : Text {
        // Validate key length
        let expectedLength = getKeyLength(did.keyType);
        if (did.publicKey.size() != expectedLength) {
            Runtime.trap("Invalid key length for " # debug_show (did.keyType) # ": expected " # Nat.toText(expectedLength) # ", got " # Nat.toText(did.publicKey.size()));
        };

        let buffer = Buffer.Buffer<Nat8>(did.publicKey.size() + 5);

        // Add multicodec prefix for key type
        let codecBytes = VarInt.encode(keyTypeToCode(did.keyType));
        for (byte in codecBytes.vals()) {
            buffer.add(byte);
        };

        // Add public key bytes
        for (byte in did.publicKey.vals()) {
            buffer.add(byte);
        };

        let multicodecKey = Buffer.toArray(buffer);
        let base58Key = BaseX.toBase58(multicodecKey.vals());

        "did:key:z" # base58Key;
    };

    /// Parses a did:key text string into a DID structure.
    ///
    /// ```motoko
    /// let result = Key.fromText("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    /// switch (result) {
    ///   case (#ok(didKey)) { /* Successfully parsed did:key */ };
    ///   case (#err(error)) { /* Handle parsing error */ };
    /// };
    /// ```
    public func fromText(text : Text) : Result.Result<DID, Text> {
        // Check format: did:key:z...
        if (not Text.startsWith(text, #text "did:key:z")) {
            return #err("Invalid did:key format: must start with 'did:key:z'");
        };

        // Extract the base58 part (everything after "did:key:z")
        let base58Part = Text.stripStart(text, #text "did:key:z");
        if (base58Part == "") {
            return #err("Invalid did:key: empty identifier");
        };

        // Decode base58
        let multicodecKey = switch (BaseX.fromBase58(base58Part)) {
            case (#ok(bytes)) bytes;
            case (#err(e)) return #err("Failed to decode base58: " # e);
        };

        if (multicodecKey.size() < 2) {
            return #err("Invalid did:key: insufficient bytes");
        };

        // Decode multicodec prefix
        let iter = Iter.fromArray(multicodecKey);
        let ?codecCode = VarInt.decode(iter) else return #err("Failed to decode multicodec prefix");
        let ?keyType = codeToKeyType(codecCode) else return #err("Unsupported key type: " # Nat.toText(codecCode));

        // Extract public key bytes
        let publicKeyBytes = Iter.toArray(iter);
        let expectedLength = getKeyLength(keyType);
        if (publicKeyBytes.size() != expectedLength) {
            return #err("Invalid key length for " # debug_show (keyType) # ": expected " # Nat.toText(expectedLength) # ", got " # Nat.toText(publicKeyBytes.size()));
        };

        #ok({
            keyType = keyType;
            publicKey = Blob.fromArray(publicKeyBytes);
        });
    };

    /// Creates a did:key from raw public key bytes and key type.
    ///
    /// ```motoko
    /// let publicKeyBytes = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
    /// let result = Key.fromPublicKey(#ed25519, publicKeyBytes);
    /// switch (result) {
    ///   case (#ok(didKey)) { /* Successfully created did:key */ };
    ///   case (#err(error)) { /* Invalid key length or format */ };
    /// };
    /// ```
    public func fromPublicKey(keyType : KeyType, publicKey : Blob) : Result.Result<DID, Text> {
        let expectedLength = getKeyLength(keyType);
        if (publicKey.size() != expectedLength) {
            return #err("Invalid key length for " # debug_show (keyType) # ": expected " # Nat.toText(expectedLength) # ", got " # Nat.toText(publicKey.size()));
        };

        #ok({
            keyType = keyType;
            publicKey = publicKey;
        });
    };

    /// Checks if two did:key DIDs are equal.
    ///
    /// ```motoko
    /// let did1 = { keyType = #ed25519; publicKey = "..."; };
    /// let did2 = { keyType = #ed25519; publicKey = "..."; };
    /// let isEqual = Key.equal(did1, did2);
    /// ```
    public func equal(did1 : DID, did2 : DID) : Bool {
        did1.keyType == did2.keyType and did1.publicKey == did2.publicKey;
    };

    /// Gets the expected byte length for a given key type.
    ///
    /// ```motoko
    /// let length = Key.getKeyLength(#ed25519);
    /// // Returns: 32
    /// ```
    public func getPublicKeyLengths(keyType : KeyType) : [Nat] {
        switch (keyType) {
            case (#ed25519) [32];
            case (#secp256k1) [33, 65];
            case (#p256) [33, 65];
        };
    };

    /// Validates that a public key has the correct length for its type.
    ///
    /// ```motoko
    /// let isValid = Key.isValidKeyLength(#ed25519, publicKeyBytes);
    /// ```
    public func isValidKeyLength(keyType : KeyType, publicKey : Blob) : Bool {
        publicKey.size() == getPublicKeyLengths(keyType);
    };

    // Convert key type to multicodec code
    private func keyTypeToCode(keyType : KeyType) : Nat {
        switch (keyType) {
            case (#ed25519) 0xed;
            case (#secp256k1) 0xe7;
            case (#p256) 0x1200;
        };
    };

    // Convert multicodec code to key type
    private func codeToKeyType(code : Nat) : ?KeyType {
        switch (code) {
            case (0xed) ?#ed25519;
            case (0xe7) ?#secp256k1;
            case (0x1200) ?#p256;
            case (_) null;
        };
    };

};
