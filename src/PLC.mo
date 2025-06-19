import Result "mo:new-base/Result";
import Nat "mo:new-base/Nat";
import Blob "mo:new-base/Blob";
import Text "mo:new-base/Text";
import Char "mo:new-base/Char";
import BaseX "mo:base-x-encoder";

module {

    /// Represents a did:plc (Public Ledger of Credentials) identifier.
    /// Used primarily in AT Protocol for decentralized identity.
    ///
    /// ```motoko
    /// let didPLC : DID = {
    ///   identifier = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    /// };
    /// ```
    public type DID = {
        identifier : Text;
    };

    /// Converts a did:plc to its text representation.
    ///
    /// ```motoko
    /// let didPLC : DID = {
    ///   identifier = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    /// };
    /// let text = PLC.toText(didPLC);
    /// // Returns: "did:plc:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    /// ```
    public func toText(did : DID) : Text {
        "did:plc:" # did.identifier;
    };

    /// Parses a did:plc text string into a DID structure.
    ///
    /// ```motoko
    /// let result = PLC.fromText("did:plc:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    /// switch (result) {
    ///   case (#ok(didPLC)) { /* Successfully parsed did:plc */ };
    ///   case (#err(error)) { /* Handle parsing error */ };
    /// };
    /// ```
    public func fromText(text : Text) : Result.Result<DID, Text> {
        // Check format: did:plc:...
        if (not Text.startsWith(text, #text "did:plc:")) {
            return #err("Invalid did:plc format: must start with 'did:plc:'");
        };

        // Extract the identifier part
        let identifier = Text.stripStart(text, #text "did:plc:");
        if (identifier == "") {
            return #err("Invalid did:plc: empty identifier");
        };

        // Validate identifier format
        switch (validateIdentifier(identifier)) {
            case (#ok(_)) {
                #ok({
                    identifier = identifier;
                });
            };
            case (#err(e)) #err(e);
        };
    };

    /// Creates a did:plc from a raw identifier string.
    ///
    /// ```motoko
    /// let result = PLC.fromIdentifier("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    /// switch (result) {
    ///   case (#ok(didPLC)) { /* Successfully created did:plc */ };
    ///   case (#err(error)) { /* Invalid identifier format */ };
    /// };
    /// ```
    public func fromIdentifier(identifier : Text) : Result.Result<DID, Text> {
        switch (validateIdentifier(identifier)) {
            case (#ok(_)) {
                #ok({
                    identifier = identifier;
                });
            };
            case (#err(e)) #err(e);
        };
    };

    /// Creates a did:plc from raw bytes by encoding them as base32.
    ///
    /// ```motoko
    /// let bytes : [Nat8] = [0x01, 0x02, 0x03, 0x04];
    /// let didPLC = PLC.fromBytes(bytes);
    /// // Returns: did:plc with base32-encoded identifier
    /// ```
    public func fromBytes(bytes : [Nat8]) : DID {
        let base32Identifier = BaseX.toBase32(bytes.vals(), #standard({ isUpper = false; includePadding = false }));
        {
            identifier = base32Identifier;
        };
    };

    /// Checks if two did:plc DIDs are equal.
    ///
    /// ```motoko
    /// let did1 = { identifier = "abc123"; };
    /// let did2 = { identifier = "abc123"; };
    /// let isEqual = PLC.equal(did1, did2);
    /// // Returns: true
    /// ```
    public func equal(did1 : DID, did2 : DID) : Bool {
        did1.identifier == did2.identifier;
    };

    /// Attempts to decode the identifier as base32 to get the original bytes.
    /// Returns an error if the identifier is not valid base32.
    ///
    /// ```motoko
    /// let didPLC : DID = { identifier = "mfrgg"; }; // base32 for "hello"
    /// switch (PLC.toBytes(didPLC)) {
    ///   case (#ok(bytes)) { /* Successfully decoded to bytes */ };
    ///   case (#err(error)) { /* Not valid base32 */ };
    /// };
    /// ```
    public func toBytes(did : DID) : Result.Result<[Nat8], Text> {
        BaseX.fromBase32(did.identifier, #standard);
    };

    /// Validates that a PLC identifier has the correct format.
    /// PLC identifiers are typically base32-encoded and follow specific patterns.
    ///
    /// ```motoko
    /// let isValid = PLC.isValidIdentifier("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    /// ```
    public func isValidIdentifier(identifier : Text) : Bool {
        switch (validateIdentifier(identifier)) {
            case (#ok(_)) true;
            case (#err(_)) false;
        };
    };

    /// Normalizes a PLC identifier to lowercase.
    ///
    /// ```motoko
    /// let normalized = PLC.normalizeIdentifier("BAFYBEIGDYRZT5SFP7UDM7HU76UH7Y26NF3EFUYLQABF3OCLGTQY55FBZDI");
    /// // Returns: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    /// ```
    public func normalizeIdentifier(identifier : Text) : Text {
        Text.map(identifier, Char.toLower);
    };

    // Validate PLC identifier format
    private func validateIdentifier(identifier : Text) : Result.Result<(), Text> {
        // Must not be empty
        if (identifier == "") {
            return #err("PLC identifier cannot be empty");
        };

        // Length constraints (PLC identifiers are typically 24-64 characters)
        if (identifier.size() < 4) {
            return #err("PLC identifier too short: minimum 4 characters");
        };

        if (identifier.size() > 64) {
            return #err("PLC identifier too long: maximum 64 characters");
        };

        // Check for valid base32 characters (case insensitive)
        let validChars = "abcdefghijklmnopqrstuvwxyz234567";
        for (char in identifier.chars()) {
            let lowerChar = Char.toLower(char);
            if (not Text.contains(validChars, #char lowerChar)) {
                return #err("Invalid character in PLC identifier: " # Char.toText(char));
            };
        };

        #ok(());
    };

};
