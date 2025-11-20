**PK-PACS Card Verifiable Certificate Specification**

Version 1.0.4
November 20, 2025



# Copyright Notice

Copyright 2025 Taglio LLC Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# Card Verifiable Certificate

This document specifies the **PK-PACS Card Verifiable Certificate (CVC)**, a compact certificate profile defined in ASN.1 and based on standard data elements and commands defined in the ISO/ 7816 series of standard.

PK-PACS CVC is analogous in structure to EAC-CVC certificate profile used in ePassports and eID Cards. PK-PACS CVC follows the same two-level ASN.1 structure (`CVCertificate` and `CertificateBody`) as the EAC-CVC, but defines its own Application-profile and certificate fields optimized for PK-PACS use.

#References#:
**EAC-CVC**: BSI TR-03110-3 (Advanced Security Mechanisms for Machine Readable Travel Documents)
ICAO Doc 9303 Part 11 (Same as BSI
PK-PACS is analogous to EAC-CVC used in Passports and specified in BSI TR-03110-3  and ICAO Doc 9303 Part 11. (Advanced Security Mechanisms for Machine Readable Travel Documents).
**7816-4**: 7816-4:2020 Part 4:  - Identification cards — Integrated circuit cards —Organization, security and commands
for interchange
**7816-6:** ISO/IEC 7816-6:2023  - Identification cards — Integrated circuit cards — Part 6: Interindustry data elements for interchange
**7816-9**   7816-19:2017 - Identification cards — Integrated circuit cards — Part 9: Commands for card management

The PK-PACS CVC:

-   is **self-descriptive**, containing its own tag numbers and field lengths;

-   consists of **BER-TLV data objects** as defined in 7816-4
    
-   employs **ASN.1 Application-class tags** defined in the 7816 tag space ensuring compatibility with BER-TLV encoding rules
    
-   uses **interindustry data objects** as defined in 7816-6, Table 7;
    
-   includes a **discretionary data template** defined in this document for encoding PK-PACS-specific OIDs and values;
    
-   follows a **defined certificate profile** with ordered data elements corresponding to the `CVCertificate` ASN.1 definition (`certificateBody` and `signature`).
   
Operationally, CVCs are:

-   **stored and managed** on-card using the data-object and life-cycle management commands defined in **ISO/IEC 7816-9** (e.g., `CREATE`, `MANAGE DATA`, `IMPORT CARD SECRET`);
    
-   **used in cryptographic operations** via the security-operation commands defined in **ISO/IEC 7816-8** (e.g., `MANAGE SECURITY ENVIRONMENT`, `PERFORM SECURITY OPERATION`, `GENERATE ASYMMETRIC KEY PAIR`);
    
-   cryptographically bound using primitives such as **ECDSA**, **ECDH**, or **RSA**, as specified in ISO/IEC 7816-8 and -15.
    
The exact structure and field ordering of the **PK-PACS CVC** are specified in the sections that follow.

# Data objects  
The following table shows the interindustry data objects used in the PK-PACS CVC. Some of the data objects have been renamed to clarify their function in PK-PACS. 

## Table 1. Interindustry data objects

| Tag   | 7816 Name                               | Len | Type             | Comment                                                                 |
|--------|------------------------------------|-----|------------------|--------------------------------------------------------------------------|
| 06     | Object Identifier                  | V   | Object Identifier | –                                                                        |
| 42     | Issuer Identification Number | 16 | Character String  | Key ID of Issuer Key                            |
| 53     | Discretionary Data                 | V   | Octet String      | Contains arbitrary data                                                  |
| 65     | Certificate Extension Data (Cardholder Related Data)            | V   | Sequence          | Nests certificate extensions                                             |
| 73     | Discretionary Data Template        | V   | Sequence          | Nests arbitrary data objects                                             |
| 5F20   | Subject Reference (Cardholder Name)      | 16 | Character String  | Key ID of subject key |
| 5F24   | Valid To                           | 6F  | Date              | The date after which the certificate expires                             |
| 5F25   | Valid From                         | 6F  | Date              | The date of the certificate generation                                   |
| 5F29   | Certificate Profile Identifier (Interchange profile)     | 1F  | Unsigned Integer  | Certificate Profile number                                                    |
| 5F37   | Signature  (Static internal authentication)                        | V   | Octet String      | –                                                                        |
| 7F21   | CV Certificate                     | V   | Sequence          | Nests certificate body and signature                                     |
| 7F49   | Public Key                         | V   | Sequence          | Nests the public key value and domain parameters                         |
| 7F4E   | Certificate Body                   | V   | Sequence          | Nests data objects of the certificate body                               |

# Certificate Profile 

The certificate profile specifies the certificate structure with the data objects.The order of data objects in the profile is fixed.   

## Table 2: PK-PACS CVC Profile Version 1

| Field (Profile v1)                         | Tag  | M/O | Comments                                       |
|--------------------------------------------|------|-----|------------------------------------------------|
| **CV Certificate**                         | 7F21 | m   | Envelope for body + signature                 |
| ├─ Certificate Body                        | 7F4E | m   | Body that concatenates all fields             |
| │  ├─ Certificate Profile Identifier| 5F29 | m   |                    |
| │  ├─ Issuer Identification Number               | 42   | m   |      |
| │  ├─ Public Key                           | 7F49 | m   |                        |
| │  ├─ Subject Reference   | 5F20 | m   |                                |
| │  ├─ Certificate Effective Date           | 5F25 | m   |                            |
| │  ├─ Certificate Expiration Date          | 5F24 | m   |                            |
| │  ├─ Certificate Extension Data| 65   | o   | When present, extensions inside                 |
| │  │  └─ Discretionary Data Object             | 73   | o*  | Each extension: 06 (OID) + 53 (value)         |
| ├─ Signature                             | 5F37 | m   | Digital signature of certificate body     
    |
# Certificate Body Field Encoding  

PK-PACS is analogous to EAC-CVC used in Passports and specified in BSI TR-03110-3  and ICAO Doc 9303 Part 11. (Advanced Security Mechanisms for Machine Readable Travel Documents).

The Distinguished Encoding Rules (DER) according to X.690 [16] SHALL be used to encode both ASN.1 data structures and (application specific) data objects. The encoding results in a Tag-Length-Value (TLV) structure as follows:  
**Tag** - The tag is encoded in one or two octets and indicates the content.  
**Length** - The length is encoded as unsigned integer in one, two, or three octets resulting in a  
maximum length of 65535 octets. The minimum number of octets shall be used.  
**Value** - The value is encoded in zero or more octets. 


# Tag 7F21 - CVC Certificate
The CVC Certificate is a container for the Certificate Body (Tag 7F4E)  and the Signature (Tag 5F37).
# Tag 7F4E - Certificate Body
The CVC Certificate Body is a container for all other certificate fields.

## Tag 5F29 - Certificate Profile Identifier

The Certificate Profile Identifier specifies the type or version of the certificate profile.   PK-PACS CVC Profile Version 1 is identified by a value of 0.  

## Tag 42 - Issuer Identification Number
The Issuer reference is the identifier for the (off card) Public Key used to verify the certificate signature.
It is a Character String of length 16 characters. 
The first 2 characters are the Country Code (ISO 3166-1 alpha-2 code) of the issuer 
The next 9 characters represent the IANA private enterprise number of the issuer, zero padded.
The last 5 characters are defined by the Issuer and can represent the sequence number.
Example: US00004498600001

## Tag 7F49 - Public Key
The Public Key consists of  either a RSA or ECC TLV sequence.

### Table 3: RSA Public Key
The data objects in an RSA public key encoding are shown in Table 3. The order of the data objects is fixed.

| Tag | Data Object Name  | Abbrev. | Type              | Option |
| -- | ---------------- | ------ | ---------------- | ----- |
| 06  | Object Identifier | —       | Object Identifier | m      |
| 81  | Composite Modulus | n       | Unsigned Integer  | m      |
| 82  | Public Exponent   | e       | Unsigned Integer  | m      |

### Table 4: Elliptic Curve Public Key
The data objects contained in an EC public key are shown in Table 4. The order of the data objects is fixed. The conditional domain parameters must be either all present, or all absent meaning there are two ways of representing a ECC key secquence, one with 2 fields, and one with 7 fields. 

| Tag | Data Object Name   | Abbrev. | Type              | Option |
| -- | -------------------- | --- | ------------------ | --------- |
| 06  | Object Identifier  | —       | Object Identifier | m      |
| 81  | Prime Modulus      | p       | Unsigned Integer  | c      |
| 82  | First Coefficient  | a       | Unsigned Integer  | c      |
| 83  | Second Coefficient | b       | Unsigned Integer  | c      |
| 84  | Base Point         | G       | EC Point          | c      |
| 85  | Order              | n       | Unsigned Integer  | c      |
| 86  | Public Point       | Q       | EC Point          | m     |

## *Subject Reference*
The Subject Reference provides a reference for the card Public key itself. It can represent an identificaiton number, or some other reference information.
It is a fixed 16 character text string defined by the issuer.

## *Dates*

A date is encoded in 6 digits `d₁ ... d₆` in the format **YYMMDD** using timezone **GMT**.
Each digit `dⱼ` (1 ≤ j ≤ 6) is encoded as **unpacked BCDs**. 
The year **YY** is encoded in two digits and is to be interpreted as **20YY**, i.e., the year is in the range **2000 to 2099**.
Example: March 15, 2025 is encoded as ‘02 05 00 03 01 05’.

### Tag 5F25 - Certificate Effective Date
The Certificate Effective Date is the date on which the certificate is signed, or the day before.

### Tag 5F25 - Certificate Expiration Date
The certificate expiration date defines the date after which the certificate expires.

## Tag 65 - Certificate Extension Data
The Certificate Extension Data is optional and shall contains one or more Discretionary Data Template data objects with PK-PACS OIDs and values, as shown in Table 5.

### Tag 73 - Discretionary Data Template
Each Discretionary Data Template data object shall be a set of Object Identifier and Discretionary Data objects.
### Table 5: Certificate Extension Data Structure
| Field                         | Tag                                         |
|--------------------------------------------|------|
| Certificate Extension Data                         | 65| 
| ├─ Discretionary Data Template                        | 7F4E | 
| │  ├─ PK-PACS OID| 06| 
| │  ├─ Value               | 53|


### Table 6: Profile v1 PK-PACS OIDs

| Name         | OID                    | DER Type       | Length (bytes) |
|---------------|------------------------|----------------|----------------|
| KeyID| 1.3.6.1.4.1.59685.7.1  | OCTET STRING   | 32|
| UUID          | 1.3.6.1.4.1.59685.8.1  | OCTET STRING   | 16             |
| 4ByteUID    | 1.3.6.1.4.1.59685.8.2  | OCTET STRING   | 4              |
| 7ByteUID    | 1.3.6.1.4.1.59685.8.3  | OCTET STRING   | 7              |
| 10ByteUID   | 1.3.6.1.4.1.59685.8.5  | OCTET STRING   | 10             |
| BinaryID     | 1.3.6.1.4.1.59685.8.7  | BIT STRING     | 25V              |
| CardInfo     | 1.3.6.1.4.1.59685.8.8  | UTF8String     | 14 V            |
| PKOC          | 1.3.6.1.4.1.59685.8.9  | OCTET STRING   | 32             |
| CardType     | 1.3.6.1.4.1.59685.8.16 | UTF8String     | 64V             |


# Certificate Signature

The **Signature** (`5F37`) authenticates the integrity and origin of the **Certificate Body** (`7F4E`). It is generated by signing the DER‑encoded bytes of the Certificate Body with the issuer’s private key.

**Algorithm and Encoding**

-   The signature algorithm corresponds to the public‑key algorithm in the `7F49` Public Key field (e.g., **ECDSA**, **RSA**).
-   The signature is encoded as an **OCTET STRING** inside tag `5F37`.
-   The hash algorithm (e.g., **SHA‑256**) is defined implicitly by the associated public‑key OID.
    
ECDSA

-   Curve: **P-256 (secp256r1)**
-   Signing algorithm: **ECDSA with SHA-256**
-   Key agreement: **ECDH (P-256) + SHA-256 KDF**
-   Symmetric encryption cipher & mode: **AES-256 in CCM mode**
-   Signature format: The signature must follow DER x9.62 encoding, but only the 64-byte “r||s” values (32 bytes r + 32 bytes s) are transmitted


**Generation Process**

1.  **Assemble Certificate Body** – concatenate and DER‑encode all `7F4E` fields in the defined order.
    
2.  **Hash** – compute the digest over the encoded Certificate Body.
    
3.  **Sign** – use the issuer’s private key to sign the hash:
    
    -   **ECDSA:** concatenate _r_ and _s_ values (e.g., 64 bytes for P‑256).- 
        
    -   **RSA:** perform modular exponentiation using PKCS #1 or PSS padding.
        
4.  **Encode** – wrap the signature bytes in a TLV with tag `5F37` and append after the Certificate Body inside `7F21`.
    
   


# Attachments 
## *CVC Example Certificate in HEX*

>  7f218201d27f4e8201825f2901014210555330303030343439383630303030317f494c06072a8648ce3d0201864101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015f2010313030303030303030303030303031315f25063235313130325f24063238313130326581f5731e060a2b0601040183d22508015310aa883f65ca7e49488a38a30b4bf6abea7312060a2b0601040183d22508025304a43ac9d37315060a2b0601040183d22508035307a1b2c3d4e5f6a07318060a2b0601040183d2250805530aa1b2c3d4e5f6a00000007312060a2b0601040183d225080a5304a0b1c2d0731c060a2b0601040183d2250808530e6132333435363731323334353630732e060a2b0601040183d225080c5320aea02aa1320054cff1dfd2f88fa583b5b059833ba87cec415abdae0791f0ec66732c060a2b0601040183d2250810531e61205461676c696f204337302d44502d444631202d2030303030303030315f37483046022100f3239b3cf8225e2ba88ac9ab110089c19c388118651b5bfb049237cd8e916646022100a96eaf265891e806149a34f1c9f70d81c41f1435469ffbe531978908f7e97b5d   

## *CVC Request*


> {
	"CVCRequest": {
		"IssuerIdentificationNumber": "US00004498600001",
		"SubjectReference": "1000000000000011",
		"PublicKey": [
			"1.2.840.10045.2.1",
			"0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"
		],
		"CertificateExtensions": {
			"UUID": "aa883f65-ca7e-4948-8a38-a30b4bf6abea",
			"4BUID": "a43AC9D3",
			"7BUID": "a1B2C3D4E5F6A0",
			"10BUID": "a1B2C3D4E5F6A0000000",
			"BinaryID": "a0B1C2D0",
			"CardInfo": "a2345671234560",
			"PKOC": "aEA02AA1320054CFF1DFD2F88FA583B5B059833BA87CEC415ABDAE0791F0EC66",
			"CardType": "a Taglio C70-DP-DF1 - 00000001"
		}
	}
}
> 


## *Common DER / ASN.1 Universal Tag Types*
> 0x04 – OCTET STRING
• Binary container for arbitrary data (byte string).
• Most X.509 and CVC extensions are wrapped in an OCTET STRING.
• May itself contain another encoded structure.
Example:
    04 06 30 04 01 01 FF
OCTET STRING of length 6, whose content is the DER for:
    SEQUENCE { BOOLEAN TRUE }

> 0x0C – UTF8String
• Human-readable text encoded in UTF-8.
• Commonly used in subject/issuer fields or for descriptive extension data.
Example:
    0C 0B 54 61 67 6C 69 6F 20 43 61 72 64
→ "Taglio Card"

> 0x03 – BIT STRING
• Bit-level data: sequences of bits, not necessarily byte-aligned.
• Used for flags (KeyUsage, SubjectKeyIdentifier) or raw public key bits.
• The first byte inside the value specifies the number of unused bits in the final byte.
Example:
    03 02 07 80
BIT STRING (2 bytes total, 7 unused bits) = 10000000b

> 0x06 – OBJECT IDENTIFIER
• Identifies an ASN.1 object type or algorithm by a dotted decimal arc.
• OIDs map to named structures (e.g., 1.2.840.10045.2.1 = ecPublicKey).
Example:
    06 07 2A 86 48 CE 3D 02 01
→ OID "1.2.840.10045.2.1"

> Tag 0x30 – SEQUENCE
• A SEQUENCE is an ordered collection of one or more TLV elements.
• It is a *constructed* type: its value is another series of encoded TLVs.
• Commonly used to group related fields (e.g., AlgorithmIdentifier,
  SubjectPublicKeyInfo, CertificateExtensions).
• When parsing, the 0x30 header gives the total length of its contents,
  and you must recursively parse all inner TLVs until that length is consumed.
Example:
    30 0A 06 03 55 1D 0E 04 03 02 01 01
SEQUENCE of length 10 containing:
    06 03 55 1D 0E   (OID 2.5.29.14, SubjectKeyIdentifier)
    04 03 02 01 01   (OCTET STRING containing BOOLEAN TRUE)



