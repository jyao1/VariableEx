/** @file

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __VARIABLE_FORMAT_EX_H__
#define __VARIABLE_FORMAT_EX_H__

#pragma pack(1)

///
/// Single Variable Data Header Structure.
///
typedef struct {
  ///
  /// Variable Data Start Flag.
  ///
  UINT16      StartId;
  ///
  /// Variable State defined above.
  ///
  UINT8       State;
  ///
  /// Attributes Extension of variable
  ///
  UINT8       AttributesEx;
  ///
  /// Attributes of variable defined in UEFI specification.
  ///
  UINT32      Attributes;
  ///
  /// Size of variable null-terminated Unicode string name.
  ///
  UINT32      NameSize;
  ///
  /// Size of the variable data without this header.
  ///
  UINT32      DataSize;
  ///
  /// A unique identifier for the vendor that produces and consumes this varaible.
  ///
  EFI_GUID    VendorGuid;
} VARIABLE_HEADER_EX;

///
/// Single Authenticated Variable Data Header Structure.
///
typedef struct {
  ///
  /// Variable Data Start Flag.
  ///
  UINT16      StartId;
  ///
  /// Variable State defined above.
  ///
  UINT8       State;
  ///
  /// Attributes Extension of variable
  ///
  UINT8       AttributesEx;
  ///
  /// Attributes of variable defined in UEFI specification.
  ///
  UINT32      Attributes;
  ///
  /// Associated monotonic count value against replay attack.
  ///
  UINT64      MonotonicCount;
  ///
  /// Associated TimeStamp value against replay attack.
  ///
  EFI_TIME    TimeStamp;
  ///
  /// Index of associated public key in database.
  ///
  UINT32      PubKeyIndex;
  ///
  /// Size of variable null-terminated Unicode string name.
  ///
  UINT32      NameSize;
  ///
  /// Size of the variable data without this header.
  ///
  UINT32      DataSize;
  ///
  /// A unique identifier for the vendor that produces and consumes this varaible.
  ///
  EFI_GUID    VendorGuid;
} AUTHENTICATED_VARIABLE_HEADER_EX;


//
// EDKII Variable driver extension for variable storage
//
#define HASH_TYPE_SHA256           0x000B
#define SHA256_DIGEST_SIZE         32

typedef struct {
  UINT32                      KeyHashType;
  UINT32                      KeyHashHeadSize; // sizeof(VARIABLE_KEY_HASH_HEADER)
  UINT8                       KeyHash[SHA256_DIGEST_SIZE];
  UINT8                       KeySalt[SHA256_DIGEST_SIZE];
} VARIABLE_KEY_HASH_HEADER;

#define SYM_TYPE_AES               0x0006
#define AES_BLOCK_SIZE             16

typedef struct {
  UINT32                      KeyDataType;
  UINT32                      KeyDataHeadSize;  // sizeof(VARIABLE_KEY_DATA_HEADER)
  UINT32                      KeyPlainDataSize; // Plain text data size
  UINT32                      KeyDataSize;      // Data size
} VARIABLE_KEY_DATA_HEADER;

//
// If EDKII_VARIABLE_KEY_AUTHENTICATED is set, the binary layout is:
// +--------------------------------+
// | (AUTHENTICATED_)VARIABLE_HEADER |
// +--------------------------------+
// |   Name                          |
// +--------------------------------+ ---> +---------------------------+
// |                                 |      | VARIABLE_KEY_HASH_HEADER  |
// |                                 |      +--------------------------+
// |   Data                          |      | VARIABLE_KEY_DATA_HEADER  |
// |                                 |      +--------------------------+
// |                                 |      |   UserData (Plain Text)   |
// +--------------------------------+ ---> +---------------------------+
//

//
// If EDKII_VARIABLE_KEY_PROTECTED is set, the binary layout is:
// +--------------------------------+
// | (AUTHENTICATED_)VARIABLE_HEADER |
// +--------------------------------+
// |   Name                          |
// +--------------------------------+ ---> +---------------------------+
// |                                 |      | VARIABLE_KEY_HASH_HEADER  |
// |                                 |      +--------------------------+
// |   Data                          |      | VARIABLE_KEY_DATA_HEADER  |
// |                                 |      +--------------------------+
// |                                 |      |   UserData (Cypher Text)  |
// +--------------------------------+ ---> +---------------------------+
//

#pragma pack()

#endif