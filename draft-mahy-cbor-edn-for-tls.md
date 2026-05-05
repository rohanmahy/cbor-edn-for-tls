---
title: "Extended Diagnostic Notation (EDN) Use with Transport Layer Security (TLS) Presentation Language (PL) Objects"
abbrev: "EDN for TLS Presentation Language"
category: info

docname: draft-mahy-cbor-edn-for-tls-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - TLS PL
 - TLS Presentation Language
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "rohanmahy/cbor-edn-for-tls"
  latest: "https://rohanmahy.github.io/cbor-edn-for-tls/draft-mahy-cbor-edn-for-tls.html"

author:
 -
    fullname: Rohan Mahy
    email: rohan.ietf@gmail.com

normative:

informative:

...

--- abstract

Extended Diagnostic Notation was designed as a superset of JSON to represent CBOR instance documents in human-readable format.
This document describes how it can be used to represent instances encoded using the TLS Presentation Language.


--- middle

# Introduction

Extended Diagnostic Notation (EDN) {{!I-D.ietf-cbor-edn-literals}} is a text format, that was originally described to represent CBOR messages as diagnostic notation in {{?RFC7094}} and then expanded in {{?RFC8949}}.
It is a superset of JSON (all valid JSON is valid EDN) that can natively represent binary content, non-finite floating point values, and additional data types (tags and simple values).
Since then it has been used to represent YAML messages, especially those that contain binary content or tags.

This document defines a convention to represent instances of binary sequences--encoded using the TLS Presentation Language (TLS PL) defined in {{Section 3 of !RFC8446}}--using EDN.
TLS encoding is used in several other protocols, for example in the Messaging Layer Security (MLS) protocol {{?RFC9420}} and the MIMI protocol {{?I-D.ietf-mimi-protocol}}.

TLS PL has a very limited set of patterns.
It deals primarily with structs and enums.
As a result, it is relatively straightforward to represent TLS encoded data if the TLS PL definitions are available.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Representation of TLS PL in EDN

EDN Representations of TLS-encoded instance data always start with the following comment line: `# ~~~ tls ` followed by the struct name, and end with the following comment line: `# ~~~`.
This allows a processor that knows TLS to convert an EDN document back into TLS-encoded binary data.

Instances of TLS-encoded structs are represented in EDN as maps with the keys equal to the names of the members.

If an enum appears that contains only the values `false (0)` and `true (1)`, its values are represented in EDN as the simple values `false` and `true`.

Instances of other TLS-encoded enums are represented as their decimal integer values with an EDN end-of-line comment naming the enum name and the item name.

Instances of the following predefined TLS numeric types: uint16, uint32, uint64, plus any variable-length integers (widely used, for example in MLS {{Section 2.1.2 of ?RFC9420}}) are represented as unsigned decimal integers in EDN.
Likewise a single instance of uint8 is represented as an unsigned decimal integer in EDN.

Vectors of uint8 (or the `opaque` type) are represented by single quoted strings in EDN.
Likewise fixed-length arrays of uint8 are represented by single quoted strings in EDN.
By default, they are presented as hex-encoded single-quoted strings.
If such sequences consist primarily of printable characters

Vectors of any other type are represented by an array of that type.

For example given the FooBar struct defined below:

~~~ tls
enum {
  false(0),
  true(1),
  (255)
} Bool;

enum {
  red(1),
  yellow(2),
  green(3)
  (255)
} Color;

struct {
  uint16 id;
  uint8[16] nonce;
  Bool active;
  Color traffic_light_color;
  uint32 divisible_by<V>;
  opaque reason;
} FooBar;
~~~

an instance of that struct could be represented as follows in EDN:

~~~ cbor-diag
# ~~~ tls FooBar
{
  "id": 16798,
  "nonce": h'f6bafb33a535d1fd05bef225d2ac8f35',
  "active": true,
  "traffic_light_color": 3,   # Color green
  "divisible_by": [3, 5, 11],
  "reason": 'server down'
}
# ~~~
~~~

## Representation of Variants

The `optional` keyword ({{Section 2.1.1 of ?RFC9420}}) is represented as a struct.
For example given the following structs:

~~~ tls
struct {
  uint16 component_id;
  opaque data;
} Component;

struct {
  uint64 epoch;
  optional<Component> component;
} Foo;
~~~

An instance of Foo which has an optional Component would be represented by the following snippet of EDN:

~~~
{
  "epoch": 42,
  "component": {
    "present": true,
    "value": {
      "component_id": 0xBABA,
      "data": h''
    }
  }
}
~~~

When absent it would be represented as:

~~~ cbor-diag
{
  "epoch": 42,
  "component": {
    "present": false
  }
}
~~~

In general, the presence of a `select` construction in TLS PL indicates the conditional presence of additional values in the struct.
For example, the struct below:

~~~ tls
{
  LeafNodeSource leaf_node_source;
  select (LeafNode.leaf_node_source) {
    case key_package:
      Lifetime lifetime;
    case update:
      struct{};
    case commit:
      opaque parent_hash<V>;
    };
  Extension extensions<V>;
} PartialLeafNode;
~~

would be represented as follows in EDN:

~~~ cbor-diag
{
  "leaf_node_source": 1, # enum LeafNodeSource.key_package
  "lifetime": {
    "not_before": 1777979674, # 05-May-2026T13:14:34Z
    "not_after":  1780312474  # 05-Jun-2026T13:14:34Z
  },
  "extensions": []
}
~~~

The notation `struct {}` in TLS PL refers to the absense of a value.
It is ignored in the representation of an EDN instance.


# Examples

## MLS LeafNode

The following detailed example represents the LeafNode struct from {{Section 7.2 of ?RFC9420}} and embedded structs.
It includes additional types from {{?I-D.ietf-mls-extensions}}, {{?I-D.ietf-mimi-room-policy}}, and {{?I-D.mahy-mls-sd-cwt-credential}}.

Given the following TLS structures:

~~~ tls
struct {
    HPKEPublicKey encryption_key;
    SignaturePublicKey signature_key;
    Credential credential;
    Capabilities capabilities;
    LeafNodeSource leaf_node_source;
    select (LeafNode.leaf_node_source) {
        case key_package:
            Lifetime lifetime;
        case update:
            struct{};
        case commit:
            opaque parent_hash<V>;
    };
    Extension extensions<V>;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    opaque signature<V>;
} LeafNode;

enum {
    reserved(0),
    key_package(1),
    update(2),
    commit(3),
    (255)
} LeafNodeSource;

struct {
    ProtocolVersion versions<V>;
    CipherSuite cipher_suites<V>;
    ExtensionType extensions<V>;
    ProposalType proposals<V>;
    CredentialType credentials<V>;
} Capabilities;

struct {
    uint64 not_before;
    uint64 not_after;
} Lifetime;


struct {
    ExtensionType extension_type;
    opaque extension_data<V>;
} Extension;

struct {
  CredentialType credential_type;
  select (Credential.credential_type) {
...
    case sd_jwt:
      SdJwt sd_jwt;
    };
} Credential;

struct {
    Bool compacted;
    select (compacted) {
        case true:
            opaque protected<V>;
            opaque payload<V>;
            opaque signature<V>;
            SdJwtDisclosure disclosures<V>;
            opaque sd_jwt_key_binding<V>;
        case false:
            opaque sd_jwt_kb<V>;
    };
} SdJwt;

enum {
  false(0),
  true(1)
} Bool;

struct {
    ComponentID component_id;
    opaque data<V>;
} ComponentData;

struct {
    ComponentData component_data<V>;
} AppDataDictionary;
AppDataDictionary app_data_dictionary;

opaque HPKEPublicKey<V>;
opaque SignaturePublicKey<V>;

/* See the "Messaging Layer Security (MLS)" IANA registries for values */
uint16 CipherSuite;
uint16 ExtensionType;
uint16 ProposalType;
uint16 CredentialType;
uint16 ComponentID;
~~~

below is an example instance represented in EDN:

~~~ cbor-diag
# ~~~ tls LeafNode
{
  "encryption_key": h'41542cd14e930f0d6db59743e2a27974
                      4d774ddc9d53679e78741787be96e832',
  "signature_key":  h'2d13ead305b4fbae97a9677a7fc04d2a
                      1778ef843121f8ffdb46c7389578768d',
  "credential": {
    "credential_type": 0x0006,  # JWT Credential Type
    "compacted": true,
    "protected": '{
      "alg": "ES256",
      "kid": "https://provider.example/jwk"
    }',
    "payload": '{
      "iss": "https://provider.example",
      "sub": "mimi://provider.example/u/alice",
      "aud": "mimi://hub.example/r/clubhouse",
      "exp": 1780312474,
      "cnf": {"jkt": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}
    }',
    "signature": h''
    "disclosures": [],
    "sd_jwt_key_binding": h'cac12ac8b387035dbdbeeed8b085d0f1
                            79f12cb1fa81218432268de12365c86c'
  },
  "capabilities": {
    "versions": [1], # ProtocolVersion mls10
    "cipher_suites": [1, 2, 3, 7],
    "extensions": [
      0x0006,   # app_data_dictionary
      0x0007,   # supported_wire_formats
      0x0008    # required_wire_formats
    ],
    "proposals": [0x0008, 0x0009, 0x000A],
    credentials: [0x0006]
  },
  "leaf_node_source": 1, # enum LeafNodeSource.key_package
  "lifetime": {
    "not_before": 1777979674, # 05-May-2026T13:14:34Z
    "not_after":  1780312474  # 05-Jun-2026T13:14:34Z
  },
  "extensions": [
    {
      "extension_type": 0x0006,  # app_data_dictionary extension
      "extension_data": [
        {
          "component_id": 0x0001, # app_components extension
          "data": [
            0x0022,   # participant_list component
            0x0024,   # mls_operational_policy component
            0x0025,   # roles-list component
            0x0027    # base_room_policy component
          ]
        },
        {
          "component_id": 0x0003, # content_media_types extension
          "data": ["application/mimi-content"]
        }
      ]
    },
    {
      "extension_type": 0xBABA.  # GREASE extension
      "extension_data": h''
    },
    {
      "extension_type": 0xDADA.  # GREASE extension
      "extension_data": h''
    }
  ],
  "signature": h'88ad994cabf15c4e90d0a4af214b1d75
                 7aecef23efffbd9d8e468866cccebac4'
}
~~~

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
