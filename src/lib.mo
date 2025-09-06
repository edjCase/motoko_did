import Result "mo:core@1/Result";
import Text "mo:core@1/Text";
import Iter "mo:core@1/Iter";
import Array "mo:core@1/Array";
import KeyModule "Key";
import PlcModule "Plc";
import WebModule "Web";

module {

  public let Web = WebModule;
  public let Key = KeyModule;
  public let Plc = PlcModule;

  /// Represents a Decentralized Identifier that can be any supported method type.
  ///
  /// ```motoko
  /// let didKey : DID = #key({
  ///   keyType = #ed25519;
  ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
  /// });
  /// let didPLC : DID = #plc({
  ///   identifier = "abc123def456";
  /// });
  /// let didWeb : DID = #web({
  ///   domain = "example.com";
  ///   path = ?["users", "alice"];
  /// });
  /// ```
  public type DID = {
    #key : KeyModule.DID;
    #plc : PlcModule.DID;
    #web : WebModule.DID;
  };

  /// Converts a DID to its text representation.
  ///
  /// ```motoko
  /// let did : DID = #key({
  ///   keyType = #ed25519;
  ///   publicKey = "\E3\B0\C4\42\98\FC\1C\14\9A\FB\F4\C8\99\6F\B9\24\27\AE\41\E4\64\9B\93\4C\A4\95\99\1B\78\52\B8\55";
  /// });
  /// let text = DID.toText(did);
  /// // Returns: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  /// ```
  public func toText(did : DID) : Text {
    switch (did) {
      case (#key(keyDid)) KeyModule.toText(keyDid, #base58btc);
      case (#plc(plcDid)) PlcModule.toText(plcDid);
      case (#web(webDid)) WebModule.toText(webDid);
    };
  };

  /// Parses a text string into a DID by auto-detecting the method.
  ///
  /// ```motoko
  /// let result = DID.fromText("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
  /// switch (result) {
  ///   case (#ok(did)) { /* Successfully parsed DID */ };
  ///   case (#err(error)) { /* Handle parsing error */ };
  /// };
  /// ```
  public func fromText(text : Text) : Result.Result<DID, Text> {
    let parts = Text.split(text, #char ':');
    let partsArray = Iter.toArray(parts);

    if (partsArray.size() < 3) {
      return #err("Invalid DID format: expected 'did:method:identifier'");
    };

    if (partsArray[0] != "did") {
      return #err("Invalid DID format: must start with 'did:'");
    };

    let method = partsArray[1];
    let remainingParts = Array.sliceToArray(partsArray, 2, partsArray.size());
    let identifier = Text.join(":", remainingParts.vals());
    let fullIdentifier = "did:" # method # ":" # identifier;

    switch (method) {
      case ("key") {
        Result.chain(
          KeyModule.fromText(fullIdentifier),
          func(keyDid : KeyModule.DID) : Result.Result<DID, Text> = #ok(#key(keyDid)),
        );
      };
      case ("plc") {
        Result.chain(
          PlcModule.fromText(fullIdentifier),
          func(plcDid : PlcModule.DID) : Result.Result<DID, Text> = #ok(#plc(plcDid)),
        );
      };
      case ("web") {
        Result.chain(
          WebModule.fromText(fullIdentifier),
          func(webDid : WebModule.DID) : Result.Result<DID, Text> = #ok(#web(webDid)),
        );
      };
      case (_) {
        #err("Unsupported DID method: " # method);
      };
    };
  };

  /// Checks if two DIDs are equal.
  ///
  /// ```motoko
  /// let did1 = #key({ keyType = #ed25519; publicKey = "..."; });
  /// let did2 = #key({ keyType = #ed25519; publicKey = "..."; });
  /// let isEqual = DID.equal(did1, did2);
  /// // Returns: true if identical
  /// ```
  public func equal(did1 : DID, did2 : DID) : Bool {
    switch (did1, did2) {
      case (#key(k1), #key(k2)) KeyModule.equal(k1, k2);
      case (#plc(p1), #plc(p2)) PlcModule.equal(p1, p2);
      case (#web(w1), #web(w2)) WebModule.equal(w1, w2);
      case (_, _) false;
    };
  };

};
