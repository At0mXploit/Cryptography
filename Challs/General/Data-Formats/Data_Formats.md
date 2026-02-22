# Cryptographic Data Formats Explained

Cryptography uses multiple layered standards. These formats often appear
together, which makes them confusing. This guide clearly separates and
explains:

-   ASN.1
-   DER
-   PEM
-   X.509
-   PKCS (especially PKCS#1 and PKCS#8)

------------------------------------------------------------------------

# ASN.1 (Abstract Syntax Notation One)

## What It Is

ASN.1 is a **data description language**, not a file format.

It defines: - Data structures - Field types - Relationships between
fields

Think of ASN.1 like a schema or blueprint.

## Example (Simplified RSA Private Key Definition)

``` asn1
RSAPrivateKey ::= SEQUENCE {
    version           INTEGER,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER   -- q
}
```

ASN.1 defines structure only --- not how it is stored or transmitted.

------------------------------------------------------------------------

# DER (Distinguished Encoding Rules)

## What It Is

DER is a **binary encoding format for ASN.1**.

It defines exactly how ASN.1 structures are serialized into bytes.

## Key Properties

-   Binary format
-   Deterministic (only one valid encoding per structure)
-   No whitespace or human readability
-   Used in certificates and keys

## Relationship

ASN.1 defines the structure. DER defines how that structure is converted
into raw bytes.

------------------------------------------------------------------------

# PEM (Privacy-Enhanced Mail)

## What It Is

PEM is a **Base64 wrapper around DER data**, with header and footer
lines.

## Example

    -----BEGIN RSA PRIVATE KEY-----
    (base64 encoded DER data)
    -----END RSA PRIVATE KEY-----

## Key Properties

-   Text format
-   Base64 encoded
-   Easy to email or paste
-   Must have exact header/footer format

## Relationship

PEM = Base64(DER) + header/footer

------------------------------------------------------------------------

# X.509

## What It Is

X.509 is a **standard for digital certificates**.

It defines: - Certificate structure - Public key storage - Issuer and
subject info - Validity period - Signature

## Structure (Simplified)

-   Version
-   Serial Number
-   Signature Algorithm
-   Issuer
-   Validity
-   Subject
-   Public Key
-   Signature

## Encoding

X.509 certificates are: - Defined using ASN.1 - Encoded using DER -
Often distributed in PEM format

------------------------------------------------------------------------

# PKCS (Public Key Cryptography Standards)

PKCS is a family of standards for cryptographic operations and storage.

## PKCS#1

Defines: - RSA key format - RSA encryption/signature standards

Used for: - Traditional RSA PRIVATE KEY blocks

PEM Header Example:

    -----BEGIN RSA PRIVATE KEY-----

------------------------------------------------------------------------

## PKCS#8

Defines: - A more general private key format - Supports multiple
algorithms (RSA, EC, etc.)

PEM Header Example:

    -----BEGIN PRIVATE KEY-----

Key Differences:

-   PKCS#1 → RSA-specific
-   PKCS#8 → Algorithm-independent wrapper

------------------------------------------------------------------------

# How They All Fit Together

Example: RSA Private Key in PEM

1.  ASN.1 defines structure
2.  DER encodes it into binary
3.  Base64 wraps it
4.  PEM adds headers

Final file = PEM formatted DER encoded ASN.1 structure

------------------------------------------------------------------------

# Quick Comparison Table

  ---------------------------------------------------------------------------
  Standard         Type          Human Readable              Purpose
  ---------------- ------------- --------------------------- ----------------
  ASN.1            Schema        No                          Defines
                   Language                                  structure

  DER              Binary        No                          Encodes ASN.1
                   Encoding                                  

  PEM              Text Encoding Yes                         Wraps DER

  X.509            Certificate   No (binary)                 Defines
                   Standard                                  certificate
                                                             structure

  PKCS#1           RSA Standard  No                          Defines RSA key
                                                             format

  PKCS#8           Key Container No                          Defines generic
                   Standard                                  private key
                                                             format
  ---------------------------------------------------------------------------

------------------------------------------------------------------------

# Summary

-   ASN.1 = Structure definition
-   DER = Binary encoding of ASN.1
-   PEM = Base64 wrapper around DER
-   X.509 = Certificate standard using ASN.1 + DER
-   PKCS#1 = RSA key standard
-   PKCS#8 = General private key container

Understanding these layers removes most confusion in cryptography file
formats.

---
