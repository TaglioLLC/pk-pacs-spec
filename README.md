# PK-PACS-Spec

This is the public repository for the current version of the PK-PACS specification.

Abstract
========

The PK-PACS Specification defines a method and data model for the support of Public Key based card authentication compatible with any existing Physical Access Control System.

The PK-PACS Specification defines how to store legacy identifiers (such as the facility and card number used by Proximity cards) into a digital certificate on a smart card. A PK-PACS compatible door reader can authenticate the card and verify the certificate with Public Key cryptography. The reader can then retrieve the legacy identifier from the card certificate and return it to the any Physical Access Control System without any changes to that system.

The PK-PACS Specification aims to ensure interoperability between Public Key enabled cards and readers, as well as readers and Physical Access Control Systems.

Introduction
============

Smart Cards are hardware security devices that are used to authenticate users and devices, and to enforce security policies on the client platforms. Smart cards that support Public Key cryptography are widely used today. Most Credit and Debit smart cards are Public Key capable, as well as SIM cards for Mobile Phones, and national identity cards. Many organizations use Smart Cards with Public Key cryptography for logon to computers and many other applications.

However, one area where Smart Cards with Public Key cryptography are not commonly used is Physical Access. Organizations that have issued smart cards to users for computer logon cannot easily use these cards for physical access.  Current systems that support Public Key cryptography for Physical Access are available, but are perceived as complex and expensive, requiring the replacement of not just readers and cards, but also the Physical Access Control hardware, and a change in processes for issuing and enrolling cards.

The PK-PACS specification simplifies the use of Smart Cards for Physical Access. PK-PACS enabled cards and readers can support any legacy Physical Access system.

