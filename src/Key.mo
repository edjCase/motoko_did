import Result "mo:core@1/Result";
import Iter "mo:core@1/Iter";
import Blob "mo:core@1/Blob";
import Text "mo:core@1/Text";
import Nat8 "mo:core@1/Nat8";
import Buffer "mo:buffer@0";
import MultiCodec "mo:multiformats@2/MultiCodec";
import MultiBase "mo:multiformats@2/MultiBase";
import List "mo:core@1/List";

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

  /// Converts a did:key to its text representation
  ///
  /// ```motoko
  /// let didKey : DID = {
  ///   keyType = #ed25519;
  ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
  /// };
  /// let text = Key.toText(didKey, #base58btc);
  /// // Returns: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  /// ```
  public func toText(did : DID, multibase : MultiBase.MultiBase) : Text {
    let key = toTextRaw(did, multibase);
    "did:key:" # key;
  };

  /// Converts a did:key to its raw text representation without the "did:key:" prefix.
  ///
  /// ```motoko
  /// let didKey : DID = {
  ///   keyType = #ed25519;
  ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
  /// };
  /// let text = Key.toTextRaw(didKey, #base58btc);
  /// // Returns: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  /// ```
  public func toTextRaw(did : DID, multibase : MultiBase.MultiBase) : Text {

    let buffer = List.empty<Nat8>();

    let codec = switch (did.keyType) {
      case (#ed25519) #ed25519Pub;
      case (#secp256k1) #secp256k1Pub;
      case (#p256) #p256Pub;
    };
    // Add multicodec prefix
    MultiCodec.toBytesBuffer(Buffer.fromList(buffer), codec);
    // Add public key bytes
    for (byte in did.publicKey.vals()) {
      List.add(buffer, byte);
    };
    // Convert to multibase (base58btc) text
    MultiBase.toText(List.values(buffer), multibase);
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

    // Extract the base58 part (everything after "did:key:")
    let base58Part = switch (Text.stripStart(text, #text "did:key:")) {
      case (?v) v;
      case (null) return #err("Invalid format: must start with 'did:key:'");
    };

    let (bytes, _) = switch (MultiBase.fromText(base58Part)) {
      case (#ok((bytes, multibase))) (bytes, multibase);
      case (#err(e)) return #err("Failed to decode multibase: " # e);
    };

    let bytesIter = bytes.vals();

    let codec = switch (MultiCodec.fromBytes(bytesIter)) {
      case (#ok(codec)) codec;
      case (#err(e)) return #err("Failed to decode multicodec: " # e);
    };

    let keyType = switch (codec) {
      case (#ed25519Pub) #ed25519;
      case (#secp256k1Pub) #secp256k1;
      case (#p256Pub) #p256;
      case (_) return #err("Unsupported key type in multicodec: " # debug_show (codec));
    };

    // Extract public key bytes
    let publicKeyBytes = Iter.toArray<Nat8>(bytesIter);

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

    #ok({
      keyType = keyType;
      publicKey = publicKey;
    });
  };

  public func equal(did1 : DID, did2 : DID) : Bool {
    did1.keyType == did2.keyType and Blob.equal(did1.publicKey, did2.publicKey)
  };

};
