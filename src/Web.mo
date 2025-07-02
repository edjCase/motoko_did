import Result "mo:new-base/Result";
import Text "mo:new-base/Text";
import Array "mo:new-base/Array";
import Iter "mo:new-base/Iter";
import Buffer "mo:base/Buffer";
import UrlKit "mo:url-kit";
import Host "mo:url-kit/Host";
import Path "mo:url-kit/Path";
import Domain "mo:url-kit/Domain";

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
        host : Host;
        port : ?Nat16;
        path : Path.Path;
    };

    public type Host = {
        #domain : Domain.Domain;
        #hostname : Text;
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
        let encodedDomain = Host.toText(did.host, did.port)
        |> Text.replace(_, #char(':'), "%3A"); // Encode colons in domain to avoid confusion with path segments
        var result = "did:web:" # encodedDomain;
        for (segment in did.path.vals()) {
            result := result # ":" # UrlKit.encodeText(segment);
        };
        result;
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

        let domainAndPath = Text.trimStart(text, #text("did:web:"));

        // Split by colons
        let parts = Text.split(domainAndPath, #char(':'));
        let partsArray = Iter.toArray(parts);

        if (partsArray.size() == 0) {
            return #err("Invalid did:web: no domain specified");
        };

        // First part is the domain
        let encodedDomain = partsArray[0] |> Text.replace(_, #text("%3A"), ":"); // Decode encoded colons
        let (host, port) : (Host, ?Nat16) = switch (Host.fromText(encodedDomain)) {
            case (#ok((#domain(domain), port))) (#domain(domain), port);
            case (#ok((#hostname(hostname), port))) (#hostname(hostname), port);
            case (#ok((#ipV4(_), _))) return #err("IPv4 addresses are not supported in did:web");
            case (#ok((#ipV6(_), _))) return #err("IPv6 addresses are not supported in did:web");
            case (#err(e)) return #err("Invalid domain encoding: " # e);
        };

        // TODO
        // // Validate domain
        // switch (Domain.validate(domain)) {
        //     case (#ok(_)) {};
        //     case (#err(e)) return #err(e);
        // };

        // Remaining parts are path segments
        let pathSegments = if (partsArray.size() > 1) {
            let encodedPath = Array.sliceToArray(partsArray, 1, partsArray.size());
            let decodedPath = Buffer.Buffer<Text>(encodedPath.size());

            for (segment in encodedPath.vals()) {
                switch (UrlKit.decodeText(segment)) {
                    case (#ok(decoded)) decodedPath.add(decoded);
                    case (#err(e)) return #err("Invalid path segment encoding: " # e);
                };
            };

            Buffer.toArray(decodedPath);
        } else {
            [];
        };

        #ok({
            host = host;
            path = pathSegments;
            port = port;
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
    public func fromDomainAndPath(domain : Text, path : [Text]) : Result.Result<DID, Text> {
        // TODO
        // // Validate domain
        // switch (Domain.validate(domain)) {
        //     case (#ok(_)) {};
        //     case (#err(e)) return #err(e);
        // };

        let domainData = switch (Domain.fromText(domain)) {
            case (#ok(domain)) domain;
            case (#err(e)) return #err("Invalid domain: " # e);
        };

        // Validate path segments
        for (segment in path.vals()) {
            if (segment == "") {
                return #err("Path segments cannot be empty");
            };
        };

        #ok({
            host = #domain(domainData);
            path = path;
            port = null;
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
        Host.equal(did1.host, did2.host) and did1.port == did2.port and Path.equal(did1.path, did2.path);
    };

    /// Gets the HTTPS URL where the DID document should be found.
    ///
    /// ```motoko
    /// let didWeb : DID = { domain = "example.com"; path = ?["users", "alice"]; };
    /// let url = Web.toHttpsUrl(didWeb);
    /// // Returns: "https://example.com/users/alice/.well-known/did.json"
    /// ```
    public func toHttpsUrl(did : DID) : Text {
        let pathText = if (did.path.size() > 0) {
            "/" # Path.toText(did.path) # "/.well-known/did.json";
        } else {
            "/.well-known/did.json";
        };
        "https://" # Host.toText(did.host, did.port) # pathText;
    };

};
