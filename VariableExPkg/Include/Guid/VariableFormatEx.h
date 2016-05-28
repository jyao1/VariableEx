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

//
// EDKII Variable driver extension for variable storage
//
#define PASSWORD_HASH_TYPE_SHA256  0x000B
#define SHA256_DIGEST_SIZE         32

typedef struct {
  UINT32                      PasswordHashType;
  UINT32                      PasswordHashHeadSize; // sizeof(VARIABLE_PASSWORD_HASH_HEADER)
  UINT8                       PasswordHash[SHA256_DIGEST_SIZE];
  UINT8                       PasswordSalt[SHA256_DIGEST_SIZE];
} VARIABLE_PASSWORD_HASH_HEADER;

#define PASSWORD_SYM_TYPE_AES      0x0006
#define AES_BLOCK_SIZE             16

typedef struct {
  UINT32                      PasswordDataType;
  UINT32                      PasswordDataHeadSize;  // sizeof(VARIABLE_PASSWORD_DATA_HEADER)
  UINT32                      PasswordPlainDataSize; // Plain text data size
  UINT32                      PasswordDataSize;      // Data size
} VARIABLE_PASSWORD_DATA_HEADER;

//
// If EFI_VARIABLE_PASSWORD_AUTHENTICATED is set, the binary layout is:
// +--------------------------------+
// | (AUTHENTICATED_)VARIABLE_HEADER |
// +--------------------------------+
// |   Name                          |
// +--------------------------------+ ---> +--------------------------------+
// |                                 |      | VARIABLE_PASSWORD_HASH_HEADER  |
// |                                 |      +--------------------------------+
// |   Data                          |      | VARIABLE_PASSWORD_DATA_HEADER  |
// |                                 |      +--------------------------------+
// |                                 |      |   UserData (Plain Text)        |
// +--------------------------------+ ---> +--------------------------------+
//

//
// If EFI_VARIABLE_PASSWORD_PROTECTED is set, the binary layout is:
// +--------------------------------+
// | (AUTHENTICATED_)VARIABLE_HEADER |
// +--------------------------------+
// |   Name                          |
// +--------------------------------+ ---> +--------------------------------+
// |                                 |      | VARIABLE_PASSWORD_HASH_HEADER  |
// |                                 |      +-------------------------------+
// |   Data                          |      | VARIABLE_PASSWORD_DATA_HEADER  |
// |                                 |      +-------------------------------+
// |                                 |      |   UserData (Cypher Text)       |
// +--------------------------------+ ---> +--------------------------------+
//

#endif