import Result "mo:core@1/Result";
import Text "mo:core@1/Text";
import Array "mo:core@1/Array";
import Iter "mo:core@1/Iter";
import UrlKit "mo:url-kit@3";
import Host "mo:url-kit@3/Host";
import Path "mo:url-kit@3/Path";
import List "mo:core@1/List";

module {

  /// Represents a did:web identifier with hostname and optional path components.
  ///
  /// ```motoko
  /// let didWeb : DID = {
  ///   hostname = "example.com";
  ///   port = null;
  ///   path = ["users", "alice"];
  /// };
  /// // Represents: did:web:example.com:users:alice
  /// ```
  public type DID = {
    hostname : Text;
    port : ?Nat16;
    path : Path.Path;
  };

  /// Converts a did:web to its text representation.
  ///
  /// ```motoko
  /// let didWeb : DID = {
  ///   hostname = "example.com";
  ///   port = null;
  ///   path = ["users", "alice"];
  /// };
  /// let text = Web.toText(didWeb);
  /// // Returns: "did:web:example.com:users:alice"
  /// ```
  public func toText(did : DID) : Text {
    let encodedHostname = Host.toText(#name(did.hostname), did.port)
    |> Text.replace(_, #char(':'), "%3A"); // Encode colons in hostname to avoid confusion with path segments
    var result = "did:web:" # encodedHostname;
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

    let hostnameAndPath = Text.trimStart(text, #text("did:web:"));

    // Split by colons
    let parts = Text.split(hostnameAndPath, #char(':'));
    let partsArray = Iter.toArray(parts);

    if (partsArray.size() == 0) {
      return #err("Invalid did:web: no hostname specified");
    };

    // First part is the hostname
    let encodedHostname = partsArray[0] |> Text.replace(_, #text("%3A"), ":"); // Decode encoded colons
    let (hostname, port) : (Text, ?Nat16) = switch (Host.fromText(encodedHostname)) {
      case (#ok((#name(hostname), port))) (hostname, port);
      case (#ok((#ipV4(_), _))) return #err("IPv4 addresses are not supported in did:web");
      case (#ok((#ipV6(_), _))) return #err("IPv6 addresses are not supported in did:web");
      case (#err(e)) return #err("Invalid hostname encoding: " # e);
    };

    // Remaining parts are path segments
    let pathSegments = if (partsArray.size() > 1) {
      let encodedPath = Array.sliceToArray(partsArray, 1, partsArray.size());
      let decodedPath = List.empty<Text>();

      for (segment in encodedPath.vals()) {
        switch (UrlKit.decodeText(segment)) {
          case (#ok(decoded)) List.add(decodedPath, decoded);
          case (#err(e)) return #err("Invalid path segment encoding: " # e);
        };
      };

      List.toArray(decodedPath);
    } else {
      [];
    };

    #ok({
      hostname = hostname;
      path = pathSegments;
      port = port;
    });
  };

  /// Creates a did:web from hostname and optional path components.
  ///
  /// ```motoko
  /// let result = Web.fromHostnameAndPath("example.com", ["users", "alice"]);
  /// switch (result) {
  ///   case (#ok(didWeb)) { /* Successfully created did:web */ };
  ///   case (#err(error)) { /* Invalid hostname or path */ };
  /// };
  /// ```
  public func fromHostnameAndPath(hostname : Text, path : [Text]) : Result.Result<DID, Text> {
    // Validate path segments
    for (segment in path.vals()) {
      if (segment == "") {
        return #err("Path segments cannot be empty");
      };
    };

    #ok({
      hostname = hostname;
      path = path;
      port = null;
    });
  };

  /// Checks if two did:web DIDs are equal.
  ///
  /// ```motoko
  /// let did1 = { hostname = "example.com"; port = null; path = ["users", "alice"]; };
  /// let did2 = { hostname = "example.com"; port = null; path = ["users", "alice"]; };
  /// let isEqual = Web.equal(did1, did2);
  /// ```
  public func equal(did1 : DID, did2 : DID) : Bool {
    Host.equal(#name(did1.hostname), #name(did2.hostname)) and did1.port == did2.port and Path.equal(did1.path, did2.path);
  };

  /// Gets the HTTPS URL where the DID document should be found.
  ///
  /// ```motoko
  /// let didWeb : DID = { hostname = "example.com"; port = null; path = ["users", "alice"]; };
  /// let url = Web.toHttpsUrl(didWeb);
  /// // Returns: "https://example.com/users/alice/.well-known/did.json"
  /// ```
  public func toHttpsUrl(did : DID) : Text {
    let pathText = if (did.path.size() > 0) {
      "/" # Path.toText(did.path) # "/.well-known/did.json";
    } else {
      "/.well-known/did.json";
    };
    "https://" # Host.toText(#name(did.hostname), did.port) # pathText;
  };

};
