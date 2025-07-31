import DID "../src";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";
import Array "mo:core/Array";
import { test } "mo:test";
import Runtime "mo:core/Runtime";

func testDid(
  expectedText : Text,
  expectedDid : DID.DID,
) {
  testDidToText(expectedDid, expectedText);
  testDidFromText(expectedText, expectedDid);
  testDidRoundtrip(expectedText);
};

func testDidToText(
  did : DID.DID,
  expectedText : Text,
) {
  let actualText = DID.toText(did);

  if (actualText != expectedText) {
    Runtime.trap(
      "Text encoding mismatch for DID" #
      "\nExpected: " # debug_show (expectedText) #
      "\nActual:   " # debug_show (actualText)
    );
  };
};

func testDidFromText(
  text : Text,
  expectedDid : DID.DID,
) {
  let actualDid = switch (DID.fromText(text)) {
    case (#ok(did)) did;
    case (#err(e)) Runtime.trap("fromText failed for '" # text # "': " # debug_show (e));
  };

  if (actualDid != expectedDid) {
    Runtime.trap(
      "Parsing mismatch for '" # text # "'" #
      "\nExpected: " # debug_show (expectedDid) #
      "\nActual:   " # debug_show (actualDid)
    );
  };
};

func testDidRoundtrip(originalText : Text) {
  let parsed = switch (DID.fromText(originalText)) {
    case (#ok(did)) did;
    case (#err(e)) Runtime.trap("Round-trip parse failed for '" # originalText # "': " # debug_show (e));
  };

  let regenerated = DID.toText(parsed);

  if (regenerated != originalText) {
    Runtime.trap(
      "Round-trip mismatch for '" # originalText # "'" #
      "\nOriginal:    " # debug_show (originalText) #
      "\nRegenerated: " # debug_show (regenerated)
    );
  };
};

func testDidError(invalidText : Text) {
  switch (DID.fromText(invalidText)) {
    case (#ok(did)) Runtime.trap("Expected error for '" # invalidText # "' but got: " # debug_show (did));
    case (#err(_)) {};
  };
};

// =============================================================================
// did:key Tests
// =============================================================================

test(
  "did:key Ed25519 - Test Vector 1",
  func() {
    testDid(
      "did:key:zQebjYihRcKtjUGhNzfTqjtJAbUmmmXMnbLHPYX3xMmgo5xhy",
      #key({
        keyType = #ed25519;
        publicKey = "\11\A2\22\A5\E7\6E\F6\94\C4\DE\85\9A\B4\32\32\5D\C1\3A\49\3B\A4\CC\62\13\02\50\86\AC\F2\B3\5D\A8\E4";
      }),
    );
  },
);

test(
  "did:key Ed25519 - Test Vector 2",
  func() {
    testDid(
      "did:key:zQecP48Csqcb6kp25JEGLhHhHTJtpJdmfo3CgJRQ1oKJur8PC",
      #key({
        keyType = #ed25519;
        publicKey = "\8F\E4\A3\5F\8B\B9\2A\B2\A4\47\3C\28\4C\C6\ED\3A\C4\C8\E6\75\2C\C8\DA\A7\28\4B\02\4B\7B\42\F0\1B\0B";
      }),
    );
  },
);

test(
  "did:key secp256k1 - Test Vector 1",
  func() {
    testDid(
      "did:key:z2kjgohdJP9HPbQATSTCuMkxVAvoQodm1ixh6eWSU9KopLo5qLh",
      #key({
        keyType = #secp256k1;
        publicKey = "\03\FA\C2\FD\4A\53\CE\6C\0B\FB\9A\6C\E7\94\05\CE\B2\5A\A2\26\47\A1\2F\06\18\5C\87\02\A4\21\85\C3\A6\56";
      }),
    );
  },
);

test(
  "did:key secp256k1 - Test Vector 2",
  func() {
    testDid(
      "did:key:zQ3shZtr1sUnrGht9Fh9GFz7X37EQxnNap24QggUSzCeZ3EBp",
      #key({
        keyType = #secp256k1;
        publicKey = "\02\B9\7C\30\DE\76\7F\51\79\84\7A\18\FA\18\ED\76\71\99\B5\7D\C5\23\78\A3\69\32\5F\94\FE\13\DE\59\F7";
      }),
    );
  },
);

test(
  "did:key P-256 - Test Vector 1",
  func() {
    testDid(
      "did:key:zDnaenzUpGTmVbramS7QkWaW52zoL5hoqPe3WDgpNY2MtXdts",
      #key({
        keyType = #p256;
        publicKey = "\03\4F\35\5B\DC\B7\CC\0A\F7\28\EF\3C\CC\EB\9D\CD\3C\1C\67\B2\26\DD\AD\1B\16\FE\0B\CD\00\7B\D4\72\F0";
      }),
    );
  },
);

// =============================================================================
// did:plc Tests
// =============================================================================

test(
  "did:plc - Standard Base32 Identifier",
  func() {
    testDid(
      "did:plc:yk4dd2qkboz2yv6tpubpc6co",
      #plc({
        identifier = "yk4dd2qkboz2yv6tpubpc6co";
      }),
    );
  },
);

// =============================================================================
// did:web Tests
// =============================================================================

test(
  "did:web - Simple Domain",
  func() {
    testDid(
      "did:web:example.com",
      #web({
        host = #domain({
          subdomains = [];
          name = "example";
          suffix = "com";
        });
        path = [];
        port = null;
      }),
    );
  },
);

test(
  "did:web - Domain with Single Path",
  func() {
    testDid(
      "did:web:example.com:user",
      #web({
        host = #domain({
          subdomains = [];
          name = "example";
          suffix = "com";
        });
        path = ["user"];
        port = null;
      }),
    );
  },
);

test(
  "did:web - Domain with Multiple Path Segments",
  func() {
    testDid(
      "did:web:example.com:users:alice",
      #web({
        host = #domain({
          subdomains = [];
          name = "example";
          suffix = "com";
        });
        path = ["users", "alice"];
        port = null;
      }),
    );
  },
);

test(
  "did:web - Subdomain",
  func() {
    testDid(
      "did:web:identity.foundation",
      #web({
        host = #domain({
          subdomains = [];
          name = "identity";
          suffix = "foundation";
        });
        path = [];
        port = null;
      }),
    );
  },
);

test(
  "did:web - Complex Path",
  func() {
    testDid(
      "did:web:example.com:accounts:corporate:acme-corp",
      #web({
        host = #domain({
          subdomains = [];
          name = "example";
          suffix = "com";
        });
        path = ["accounts", "corporate", "acme-corp"];
        port = null;
      }),
    );
  },
);

test(
  "did:web - Port Number in Domain",
  func() {
    testDid(
      "did:web:localhost%3A8080",
      #web({
        host = #hostname("localhost");
        port = ?8080;
        path = [];
      }),
    );
  },
);

test(
  "did:web - URL Encoded Characters",
  func() {
    testDid(
      "did:web:example.com:path%20with%20spaces",
      #web({
        host = #domain({
          subdomains = [];
          name = "example";
          suffix = "com";
        });
        path = ["path with spaces"];
        port = null;
      }),
    );
  },
);

// =============================================================================
// Round-trip Tests (Additional Cases)
// =============================================================================

test(
  "Round-trip: Various did:key formats",
  func() {
    testDidRoundtrip("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    testDidRoundtrip("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
    testDidRoundtrip("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv");
  },
);

test(
  "Round-trip: Various did:plc formats",
  func() {
    testDidRoundtrip("did:plc:yk4dd2qkboz2yv6tpubpc6co");
  },
);

test(
  "Round-trip: Various did:web formats",
  func() {
    testDidRoundtrip("did:web:example.com");
    testDidRoundtrip("did:web:example.com:users:alice");
    testDidRoundtrip("did:web:localhost%3A8080");
    testDidRoundtrip("did:web:example.com:path%20with%20spaces");
  },
);

// =============================================================================
// Error Cases
// =============================================================================

test(
  "Error Cases: Invalid DID Formats",
  func() {
    testDidError("");
    testDidError("not-a-did");
    testDidError("did:");
    testDidError("did:invalid");
    testDidError("did:unsupported:123");
  },
);

test(
  "Error Cases: Invalid did:key",
  func() {
    testDidError("did:key:");
    testDidError("did:key:not-base58");
    testDidError("did:key:z");
    testDidError("did:key:z123");
  },
);

test(
  "Error Cases: Invalid did:plc",
  func() {
    testDidError("did:plc:");
    testDidError("did:plc:ab");
    testDidError("did:plc:invalid@chars");
    testDidError("did:plc:" # Text.fromArray(Array.fromVarArray(VarArray.repeat<Char>('a', 70))));
  },
);

test(
  "Error Cases: Invalid did:web",
  func() {
    testDidError("did:web:");
    testDidError("did:web:-invalid.com");
    testDidError("did:web:invalid-.com");
    testDidError("did:web:.invalid.com");
    testDidError("did:web:invalid.com.");
  },
);
