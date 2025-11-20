# PK-PACS - Credential Specification

Draft v1.0.6
November 20, 2025

# Copyright Notice

Copyright 2025 Taglio LLC Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# Introduction
This document describes the credential identifiers supported by the PK-PACS specification. 

For clarity this document uses the following terms: Card, Digital Credential and Credential ID:

**Card**: the physical device that contains one or more digital credentials. 
A card contains a secure chip (also known as secure element) that secures the signing keys, performs cryptography and may also execute the communication with a reader.

**Digital Credential**: A cryptographic structure that contains one or more Credential IDs. 
PK-PACS currently supports 3 Digital Credential Types:
 1. *X509 Certificates*: Digital Certificates as defined in a set of standards by the IETF's PKIX working group.  
 2. *CVC Certificates*: The Card Verifiable Certificate (CVC) specification as defined in ISO/IEC 7816-8.
 3. *JSON Objects*: JSON Objects such as JWS (RFC 7515) and JWT (RFC 7519)

**Credential ID**: A number or binary object that represents the card or cardholder
Credential IDs includes legacy PACS Credential IDs, as well as credential IDs specific to a Digital Credential Type, such as x509.

# PK-PACS Data Types

To enable interchange of PK-PACS data between systems, and to enable definition of PK-PACS data in this document, PK-PACS uses a restricted subset of the JSON Data Interchange Format, RFC 8259. All data is encoded using UTF-8, and only the following primitives are supported:
**Number**: Base-10 integer representing a number
**String**: a sequence of Unicode Characters enclosed in quotation marks
The following string types are supported:
- OID: String containing a valid PK-PACS ID-OID that defines a value, or that is a key to a Valu
- Hexidecimal: String representing Base-16 Binary Data that is a multiple of whole bytes
- Binary: String representing Base-2 Data of any bit length
- Text: String intended to be read by Humans

Appendix A provides a JSON Schema that defines these data formats.

**Key / Value Representation**
A OID and a Value separated by a ":"  Example:

**File encoding**
- Files containing PK-PACS data must be encoded in UTF-8

 **Examples**
> Hexadecimal
> "1.3.6.1.4.1.59685.8.1":"550e8400e29b41d4a716446655443211"
> Binary
> "1.3.6.1.4.1.59685.8.6.1":"10111101110110010000111100"
> Text
> "1.3.6.1.4.1.59685.8.16":"Taglio E2192-DF2  08-12-2025"

# PK-PACS Credential IDs
PK-PACS specifies a set of OIDs to represent legacy Credential IDs commonly used by current PACS systems. OIDs that represent card identifiers are known as ID-OIDs to distinguish them from any other OIDs in the credential. There are ID-OIDs for different types of card identifiers, and a single Card Credential can have multiple ID-OIDs.

ID-OIDs are represented as a sub branch of the PK-PACS OID root. This root is registered as an IANA enterprise number with the prefix "1.3.6.1.4.1.59685".  The sub branch for ID-OIDS is "1.3.6.1.4.1.59685.8". 

The following sections specify how identifiers that can be used for physical access are represented in digital credentials, so that they can be used in a physical access system. 

## Binary ID
A common type of legacy card number is the binary number used by 125KhZ Proximity cards.  Almost all legacy physical access systems support binary numbers up to a length of 37 bits.

Binary numbers are encoded and written to the credential to personalize the card. The structure of the encoding is known as a format. Typically the format includes a card number, and often includes a site or facility code.  Formats may include different types of checksums and proprietary encoding methods.  For example, a very common format is known as H10301, and is represented by 26 bits: "1011001000011000000111001". This includes a leading and trailing parity bit, 8 bits for the facility code, and 16 bits for the card serial number.

PK-PACS specifies the Binary Number ID-OID to store the complete binary number. This can be constructed, or read from the card, if it is already encoded. Information about the format can be optionally included in the Card Info ID-OID. 

## UIDs

UIDs are card numbers assigned by the card manufacturer or issuer that are not programmed for a specific project and are unique across all related products. The most widely used UID type in physical access are those defined by the ISO 14443 specification for contactless cards. ISO 14443 specifies 4, 7 and 10 byte UIDs.  As an example, the DESFire® line of products from NXP uses the 7 Byte UID. ISO 14443 requires that all UIDs of 7 or 10 bytes must be unique across al 14443 devices..

PK-PACS also includes the UUID ID-OID compliant with RFC 4122. This is a 128 bit binary number. 

## Other Credential IDs
Many card vendors print personalized text on the card. This text allows the card to be visually identified and may include the SKU or Type Name, Order ID, batch number and UID. The Card Info ID-OID may be used to store this information in the card credential. The Card Info OID value may also contain additional information specific to the card.

The Card Type ID OID includes information about the type of the card.  This may be a SKU, product name, or order number for the card batch.

The PK-PACS UHF UID can contain the ISO/IEC 18000-6C  Tag Identifiers (TID) of 4-20 bytes length. 

The PKOC ID-OID is used for a PKOC (Public Key Open Credential) identifier.  The PKOC ID-OID should be used for the PKOC identifier when a seperate PKOC NFC application is on the card.
 
## Table 1A: PK-PACS Credential IDs

| Name  | ID-OID     | Type        | Byte Length | Notes |
|-----------------|------------|----------------------|------------|-------|
| UUID            | 1.3.6.1.4.1.59685.8.1  |Hexadecimal    | 16|UUID (RFC 4122)     |
| 4ByteUID| 1.3.6.1.4.1.59685.8.2  |Hexadecimal    | 4|ISO 14443 UID such as MIFARE® Classic|
| 7ByteUID| 1.3.6.1.4.1.59685.8.3  |Hexadecimal    | 7| ISO 14443 UID such as DESFIRE® |
| 10ByteUID   | 1.3.6.1.4.1.59685.8.5  |Hexadecimal    | 10|ISO 14443 UID |
| BinaryID| 1.3.6.1.4.1.59685.8.7| Binary | Var ≤25| ID of any bit length |
| CardInfo        | 1.3.6.1.4.1.59685.8.8  | Text       | 14| Human-readable Card Specific Info |
| PKOC            | 1.3.6.1.4.1.59685.8.9 |Hexadecimal    | 32| Full ECC-P256 Public Key |
| CardType       |1.3.6.1.4.1.59685.8.16 | Text| Var ≤64| Human-readable Card Type, Order Info or SKU |

## Table 1B: PK-PACS Proximity Formats

Arc 1.3.6.1.4.1.59685.8.6 is reserved for components that describe the proximity format of the Binary ID (1.3.6.1.4.1.59685.8.7). These components do not have a value associated.

| Name | ID-OID     | Notes |
|-----------------|------------|----------------------|------------|-------|
| Prox ND| 1.3.6.1.4.1.59685.8.6.1  |Prox Format Not Defined|
| H10301 | 1.3.6.1.4.1.59685.8.6.2  |Standard 26-bit format |
| H10304 | 1.3.6.1.4.1.59685.8.6.3  |Like HID® with Facility Code|
| 40134| 1.3.6.1.4.1.59685.8.6.4  |Like Indala® |


## Table 1C: UHF TID

Arc  1.3.6.1.4.1.59685.8.4 is reserved for UHF Identifiers and their values. PK-PACS supports UHF device tags with Tag Identifiers compliant to ISO/IEC 18000-6C. 

| Name | ID-OID     | Type        | Byte Length | Notes |
|-----------------|------------|----------------------|------------|-------|
| UHF Short TID | 1.3.6.1.4.1.59685.8.4.1  |Hexadecimal           | 4 | Manufacturer & type only|
| UHF Serial TID   | 1.3.6.1.4.1.59685.8.4.2 |Hexadecimal          | 8 | Serialized like Alien® Higgs®|
| UHF XTID| 1.3.6.1.4.1.59685.8.4.3  |Hexadecimal           | 12| Extended TID like Impinj® Monza®|
| UHF Info| 1.3.6.1.4.1.59685.8.4.4 | Text          | 16| Human readable text with UHF info|

## Table 1D: PACS Data Objects

Arc 1.3.6.1.4.1.59685.8.17 is reserved for PACS Data Objects (PDO)  introduced in NXP® application note AN10957 for the DESFIRE® card. In PK-PACS the PACS Data Object must be handled as a opaque binary object. However, applications using the PDO may parse the PACS Data Object to extract one or more of the fields, such as the Site Code and Credential ID. The PDO Full ID-OID contains all fields. The Short ID-OID contains Site and Credential ID only. The LEAF® Community has published several variants of the PACS Data Object.  PK-PACS supports the LEAF Universal Memory Specification Version 4 variant as PDO Universal.

| Identifier Name | ID-OID     | Raw Value Type        | Raw Length | Notes |
|-----------------|------------|----------------------|------------|-------|
| PDO Full      | 1.3.6.1.4.1.59685.8.17.1 | Hexadecimal            | 48| All AN10957 fields|
| PDO Short     | 1.3.6.1.4.1.59685.8.17.2 | Hexadecimal             | 13| AN10957 Site and ID Only|
| PDO Universal| 1.3.6.1.4.1.59685.8.17.3 | Hexadecimal             | 64| LEAF® v4 Data Model|
| PDO Info| 1.3.6.1.4.1.59685.8.17.3 | Hexadecimal              | 16| Human readable text with PDO info|

## Table 2A: x509 Certificate Credential IDs

In addition to Legacy Card Identifiers defined in the PK-PACS ID-OIDs, there are existing OIDs commonly found in x509 certificates that can also be used as ID-OIDs in physical Access Systems. 

The Subject Key Identifier (SKI) is a certificate extension that provides a unique identifier for the public key contained within the certificate.  It typically consists of a 20-byte HSA1 hash value or 32-byte SHA256 hash value generated from the certificate's public key.

The certificate Serial Number is assigned by the certificate authority, and uniquely identifies the certificate to the certificate authority that signed the certificate. Current standards require the certificate number to be at least 32 bits long, and generated using a random number generator. 

In addition there are two additional UID identifiers that are widely used that are specific to x509/PKIX applications, and are stored in the Subject Alternative Name extensions, the UUID (URN) and the GUID.

Finally there is the AKI, or Authority Key Identifier that uniquely identifies the trust anchor that has signed the certificate.  In x509 this is typically a intermediate certificate authority.

| Identifier Name   | ID-OID                | Raw Value Type            | Raw Length    |
|-------------------|-----------------------|---------------------------|---------------|
| SKI               | 2.5.29.14             | Hexadecimal     | 20 or 32 bytes|
| Serial Number   | 2.5.4.5                | Hexadecimal       |Variable| 
| SAN UUID    | 2.5.29.17             | Hexadecimal       | 16 bytes   |
| SAN GUID     | 1.3.6.1.4.1.311.25.1  | Hexadecimal     | 16 bytes   |
| AKI             | 2.5.29.35              | Hexadecimal        | Variable |                    


## Table 2B: Public Key Credential IDs

The Public Key may be used as a Credential ID by itself. 

| Identifier Name   | ID-OID                | Raw Value Type            | Raw Length    |
|-------------------|-----------------------|---------------------------|---------------|
| RSA Public Key    | 1.2.840.113549.1.1.1  | Hexadecimal     | Variable      |
| ECC Public Key    | 1.2.840.10045.2.1     | Hexadecimal     | 32–66 bytes   |


## Table 2C Hash Based Credential IDs

Derived Credential IDs are not contained in the credential itself.  They are derived from the credential, or data in the credential. ID-OIDs are assigned to the Hash and Thumbprint for usage in configuration and verification.  They are not stored in the credential itself. The PK Hash is calculated from the Public Key in the credential.  Correctly calculated, this should be the same value as the SKI if the SKI is in the credential. Another derived credential ID is the "Thumbprint" of a x509 certificate or other credential. This is the Cryptographic Hash of the entire credential.  For a x509 certificate, this is the complete binary DER-encoded certificate data. For JSON, this is the  BASE64URL signature of the header and payload. PK-PACS supports SHA1 and SHA256 thumbprints.

| Identifier Name   | ID-OID                | Raw Value Type            | Raw Length    |
|-------------------|-----------------------|---------------------------|---------------|
| PK Hash    | 1.3.6.1.4.1.59685.9.1  | Hexadecimal     | 20-32 Bytes|
| Thumbprint    | 1.3.6.1.4.1.59685.9.2  | Hexadecimal      | 32–66 bytes   |

## Appendix A:  PK-PACS Data Format Schema
#Data Schema
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "number": {
      "type": "integer",
      "description": "Base-10 integer representing a number"
    },
    "hexadecimal": {
      "type": "string",
      "pattern": "^([A-Fa-f0-9]{2})+$",
      "description": "String representing Base-16 binary data as whole bytes"
    },
    "binary": {
      "type": "string",
      "pattern": "^[01]+$",
      "description": "String representing binary data of any bit length"
    },
    "text": {
      "type": "string",
      "description": "Human-readable string"
    },
    "oid": {
      "type": "string",
      "pattern": "^(\\d+\\.)+\\d+$",
      "description": "PK-PACS ID-OID string key to a value (dot-separated"
    },
  },
  "required": [
    "number", "hexadecimal", "binary", "text", "oid", "arc"
  ]
}

