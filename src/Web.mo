import Result "mo:new-base/Result";
import Text "mo:new-base/Text";
import Char "mo:new-base/Char";
import Array "mo:new-base/Array";
import Iter "mo:new-base/Iter";
import Buffer "mo:base/Buffer";

module {

    /// Represents a did:web identifier with domain and optional path components.
    ///
    /// ```motoko
    /// let didWeb : DID = {
    ///   domain = "example.com";
    ///   path = ?["users", "alice"];
    /// };
    /// // Represents: did:web:example.com:users:alice
    /// ```
    public type DID = {
        domain : Text;
        path : ?[Text];
    };

    /// Converts a did:web to its text representation.
    ///
    /// ```motoko
    /// let didWeb : DID = {
    ///   domain = "example.com";
    ///   path = ?["users", "alice"];
    /// };
    /// let text = Web.toText(didWeb);
    /// // Returns: "did:web:example.com:users:alice"
    /// ```
    public func toText(did : DID) : Text {
        let encodedDomain = urlEncode(did.domain);
        var result = "did:web:" # encodedDomain;

        switch (did.path) {
            case (null) result;
            case (?pathArray) {
                for (segment in pathArray.vals()) {
                    result := result # ":" # urlEncode(segment);
                };
                result;
            };
        };
    };

    /// Parses a did:web text string into a DID structure.
    ///
    /// ```motoko
    /// let result = Web.fromText("did:web:example.com:users:alice");
    /// switch (result) {
    ///   case (#ok(didWeb)) { /* Successfully parsed did:web */ };
    ///   case (#err(error)) { /* Handle parsing error */ };
    /// };
    /// ```
    public func fromText(text : Text) : Result.Result<DID, Text> {
        // Check format: did:web:...
        if (not Text.startsWith(text, #text "did:web:")) {
            return #err("Invalid did:web format: must start with 'did:web:'");
        };

        // Extract the part after "did:web:"
        let remainder = Text.stripStart(text, #text "did:web:");
        if (remainder == "") {
            return #err("Invalid did:web: empty identifier");
        };

        // Split by colons
        let parts = Text.split(remainder, #char ':');
        let partsArray = Iter.toArray(parts);

        if (partsArray.size() == 0) {
            return #err("Invalid did:web: no domain specified");
        };

        // First part is the domain
        let encodedDomain = partsArray[0];
        let domain = switch (urlDecode(encodedDomain)) {
            case (#ok(decoded)) decoded;
            case (#err(e)) return #err("Invalid domain encoding: " # e);
        };

        // Validate domain
        switch (validateDomain(domain)) {
            case (#ok(_)) {};
            case (#err(e)) return #err(e);
        };

        // Remaining parts are path segments
        let pathSegments = if (partsArray.size() > 1) {
            let encodedPath = Array.sliceToArray(partsArray, 1, partsArray.size());
            let decodedPath = Buffer.Buffer<Text>(encodedPath.size());

            for (segment in encodedPath.vals()) {
                switch (urlDecode(segment)) {
                    case (#ok(decoded)) decodedPath.add(decoded);
                    case (#err(e)) return #err("Invalid path segment encoding: " # e);
                };
            };

            ?Buffer.toArray(decodedPath);
        } else {
            null;
        };

        #ok({
            domain = domain;
            path = pathSegments;
        });
    };

    /// Creates a did:web from domain and optional path components.
    ///
    /// ```motoko
    /// let result = Web.fromDomainAndPath("example.com", ?["users", "alice"]);
    /// switch (result) {
    ///   case (#ok(didWeb)) { /* Successfully created did:web */ };
    ///   case (#err(error)) { /* Invalid domain or path */ };
    /// };
    /// ```
    public func fromDomainAndPath(domain : Text, path : ?[Text]) : Result.Result<DID, Text> {
        // Validate domain
        switch (validateDomain(domain)) {
            case (#ok(_)) {};
            case (#err(e)) return #err(e);
        };

        // Validate path segments if present
        switch (path) {
            case (null) {};
            case (?pathArray) {
                for (segment in pathArray.vals()) {
                    if (segment == "") {
                        return #err("Path segments cannot be empty");
                    };
                };
            };
        };

        #ok({
            domain = domain;
            path = path;
        });
    };

    /// Checks if two did:web DIDs are equal.
    ///
    /// ```motoko
    /// let did1 = { domain = "example.com"; path = ?["users", "alice"]; };
    /// let did2 = { domain = "example.com"; path = ?["users", "alice"]; };
    /// let isEqual = Web.equal(did1, did2);
    /// ```
    public func equal(did1 : DID, did2 : DID) : Bool {
        if (did1.domain != did2.domain) return false;

        switch (did1.path, did2.path) {
            case (null, null) true;
            case (?path1, ?path2) {
                if (path1.size() != path2.size()) return false;
                for (i in path1.keys()) {
                    if (path1[i] != path2[i]) return false;
                };
                true;
            };
            case (_, _) false;
        };
    };

    /// Gets the HTTPS URL where the DID document should be found.
    ///
    /// ```motoko
    /// let didWeb : DID = { domain = "example.com"; path = ?["users", "alice"]; };
    /// let url = Web.toHttpsUrl(didWeb);
    /// // Returns: "https://example.com/users/alice/.well-known/did.json"
    /// ```
    public func toHttpsUrl(did : DID) : Text {
        var url = "https://" # did.domain;

        switch (did.path) {
            case (null) ();
            case (?pathArray) {
                for (segment in pathArray.vals()) {
                    url := url # "/" # urlEncodeForPath(segment);
                };
            };
        };
        url # "/.well-known/did.json";
    };

    /// Validates a domain name according to basic DNS rules.
    ///
    /// ```motoko
    /// let isValid = Web.isValidDomain("example.com");
    /// // Returns: true
    /// ```
    public func isValidDomain(domain : Text) : Bool {
        switch (validateDomain(domain)) {
            case (#ok(_)) true;
            case (#err(_)) false;
        };
    };

    /// Normalizes a domain to lowercase.
    ///
    /// ```motoko
    /// let normalized = Web.normalizeDomain("EXAMPLE.COM");
    /// // Returns: "example.com"
    /// ```
    public func normalizeDomain(domain : Text) : Text {
        Text.map(domain, Char.toLower);
    };

    // Validate domain format
    private func validateDomain(domain : Text) : Result.Result<(), Text> {
        if (domain == "") {
            return #err("Domain cannot be empty");
        };

        if (domain.size() > 253) {
            return #err("Domain too long: maximum 253 characters");
        };

        // Check for valid domain characters
        for (char in domain.chars()) {
            if (not isValidDomainChar(char)) {
                return #err("Invalid character in domain: " # Char.toText(char));
            };
        };

        // Cannot start or end with hyphen or dot
        if (Text.startsWith(domain, #char '-') or Text.endsWith(domain, #char '-')) {
            return #err("Domain cannot start or end with hyphen");
        };

        if (Text.startsWith(domain, #char '.') or Text.endsWith(domain, #char '.')) {
            return #err("Domain cannot start or end with dot");
        };

        #ok(());
    };

    // Check if character is valid in domain name
    private func isValidDomainChar(char : Char) : Bool {
        let code = Char.toNat32(char);
        // Letters, digits, hyphens, dots
        (code >= 97 and code <= 122) or // a-z
        (code >= 65 and code <= 90) or // A-Z
        (code >= 48 and code <= 57) or // 0-9
        code == 45 or // hyphen
        code == 46; // dot
    };

    // URL encode a string (basic implementation)
    private func urlEncode(text : Text) : Text {
        let buffer = Buffer.Buffer<Text>(text.size());
        for (char in text.chars()) {
            let code = Char.toNat32(char);
            if (isUnreservedChar(char)) {
                buffer.add(Char.toText(char));
            } else {
                buffer.add("%" # natToHex(code));
            };
        };
        Text.join("", buffer.vals());
    };

    // URL encode for path segments (slightly different rules)
    private func urlEncodeForPath(text : Text) : Text {
        let buffer = Buffer.Buffer<Text>(text.size());
        for (char in text.chars()) {
            if (isUnreservedChar(char) or char == '/' or char == '-' or char == '_' or char == '.') {
                buffer.add(Char.toText(char));
            } else {
                let code = Char.toNat32(char);
                buffer.add("%" # natToHex(code));
            };
        };
        Text.join("", buffer.vals());
    };

    // URL decode a string (basic implementation)
    private func urlDecode(text : Text) : Result.Result<Text, Text> {
        let buffer = Buffer.Buffer<Text>(text.size());
        let chars = Iter.fromArray(Text.toArray(text));

        label w while (true) {
            switch (chars.next()) {
                case (null) break w;
                case (?'%') {
                    // Decode hex sequence
                    let ?hex1 = chars.next() else return #err("Incomplete percent encoding");
                    let ?hex2 = chars.next() else return #err("Incomplete percent encoding");

                    switch (hexToNat(Char.toText(hex1) # Char.toText(hex2))) {
                        case (#ok(code)) {
                            buffer.add(Char.toText(Char.fromNat32(code)));
                        };
                        case (#err(e)) return #err("Invalid hex in percent encoding: " # e);
                    };
                };
                case (?char) {
                    buffer.add(Char.toText(char));
                };
            };
        };

        #ok(Text.join("", buffer.vals()));
    };

    // Check if character is unreserved (doesn't need encoding)
    private func isUnreservedChar(char : Char) : Bool {
        let code = Char.toNat32(char);
        (code >= 65 and code <= 90) or // A-Z
        (code >= 97 and code <= 122) or // a-z
        (code >= 48 and code <= 57) or // 0-9
        char == '-' or char == '.' or char == '_' or char == '~';
    };

    // Convert Nat32 to hex string
    private func natToHex(n : Nat32) : Text {
        let digits = "0123456789ABCDEF";
        let high = Nat32.toNat(n / 16);
        let low = Nat32.toNat(n % 16);
        Text.fromChar(Text.toArray(digits)[high]) # Text.fromChar(Text.toArray(digits)[low]);
    };

    // Convert hex string to Nat32
    private func hexToNat(hex : Text) : Result.Result<Nat32, Text> {
        if (hex.size() != 2) {
            return #err("Hex string must be exactly 2 characters");
        };

        let chars = Text.toArray(hex);
        let ?high = hexCharToNat(chars[0]) else return #err("Invalid hex character: " # Char.toText(chars[0]));
        let ?low = hexCharToNat(chars[1]) else return #err("Invalid hex character: " # Char.toText(chars[1]));

        #ok(Nat32.fromNat(high * 16 + low));
    };

    // Convert hex character to Nat
    private func hexCharToNat(char : Char) : ?Nat {
        let code = Char.toNat32(char);
        if (code >= 48 and code <= 57) {
            // 0-9
            ?Nat32.toNat(code - 48);
        } else if (code >= 65 and code <= 70) {
            // A-F
            ?Nat32.toNat(code - 55);
        } else if (code >= 97 and code <= 102) {
            // a-f
            ?Nat32.toNat(code - 87);
        } else {
            null;
        };
    };

};
