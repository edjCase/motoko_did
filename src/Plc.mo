import Result "mo:core@1/Result";
import Text "mo:core@1/Text";

module {

  /// Represents a did:plc (Public Ledger of Credentials) identifier.
  /// Used primarily in AT Protocol for decentralized identity.
  public type DID = {
    identifier : Text;
  };

  /// Converts a did:plc to its text representation.
  ///
  /// ```motoko
  /// let didPLC : DID = {
  ///   identifier = "yk4dd2qkboz2yv6tpubpc6co";
  /// };
  /// let text = PLC.toText(didPLC);
  /// // Returns: "did:plc:yk4dd2qkboz2yv6tpubpc6co"
  /// ```
  public func toText(did : DID) : Text {
    "did:plc:" # did.identifier;
  };

  /// Parses a did:plc text string into a DID structure.
  ///
  /// ```motoko
  /// let result = PLC.fromText("did:plc:yk4dd2qkboz2yv6tpubpc6co");
  /// switch (result) {
  ///   case (#ok(didPLC)) { /* Successfully parsed did:plc */ };
  ///   case (#err(error)) { /* Handle parsing error */ };
  /// };
  /// ```
  public func fromText(text : Text) : Result.Result<DID, Text> {
    // Extract the identifier part
    let identifierText = Text.trimStart(text, #text("did:plc:"));
    if (identifierText.size() != 24) {
      return #err("Invalid identifier length: must be 24 characters");
    };
    let normalized = Text.toLower(identifierText);
    return #ok({ identifier = normalized });
  };

  /// Checks if two did:plc DIDs are equal.
  ///
  /// ```motoko
  /// let did1 = { identifier = "yk4dd2qkboz2yv6tpubpc6co"; };
  /// let did2 = { identifier = "yk4dd2qkboz2yv6tpubpc6co"; };
  /// let isEqual = PLC.equal(did1, did2);
  /// // Returns: true
  /// ```
  public func equal(did1 : DID, did2 : DID) : Bool {
    Text.toLower(did1.identifier) == Text.toLower(did2.identifier);
  };

};
