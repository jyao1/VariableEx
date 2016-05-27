/** @file

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PASSWORD_LIB_H__
#define __PASSWORD_LIB_H__

/**
  Generate Salt value.

  @param[in, out]   SaltValue           Points to the salt buffer
  @param[in]        SaltSize            Size of the salt buffer

**/
VOID
EFIAPI
PasswordLibGenerateSalt(
  IN OUT UINT8  *SaltValue,
  IN UINTN      SaltSize
  );

//
// Only SHA256 is supported in this version
//
#define PASSWORD_HASH_TYPE_SHA256  0x000B
#define PASSWORD_SYM_TYPE_AES      0x0006

#define AES_BLOCK_SIZE  16

/**
  Hash the data.

  @param[in]   HashType       Hash type
  @param[in]   Password       Points to the password buffer
  @param[in]   PasswordSize   Password buffer size
  @param[in]   SaltValue      Points to the salt buffer
  @param[in]   SaltSize       Size of the salt buffer
  @param[out]  PasswordHash   Points to the hashed result

  @retval      TRUE           Hash the data successfully.
  @retval      FALSE          Failed to hash the data.

**/
BOOLEAN
EFIAPI
PasswordLibGenerateHash(
  IN   UINT32              HashType,
  IN   VOID                *Password,
  IN   UINTN               PasswordSize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  OUT  UINT8               *PasswordHash
  );

/**
  Encrypt the data.

  InputDataSize must be block size aligned.

  @param[in]   SymType        Symetric Encryption type
  @param[in]   Password       Points to the password buffer
  @param[in]   PasswordSize   Password buffer size
  @param[in]   SaltValue      Points to the salt buffer
  @param[in]   SaltSize       Size of the salt buffer
  @param[in]   InputData      Points to the input data
  @param[in]   InputDataSize  Size of the input data
  @param[out]  OutputData     Points to the output data

  @retval      TRUE           Encrypt the data successfully.
  @retval      FALSE          Failed to encrypt the data.

**/
BOOLEAN
EFIAPI
PasswordLibEncrypt(
  IN   UINT32              SymType,
  IN   VOID                *Password,
  IN   UINTN               PasswordSize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  IN   VOID                *InputData,
  IN   UINTN               InputDataSize,
  OUT  VOID                *OutputData
  );

/**
  Decrypt the data.

  InputDataSize must be block size aligned.

  @param[in]   SymType        Symetric Encryption type
  @param[in]   Password       Points to the password buffer
  @param[in]   PasswordSize   Password buffer size
  @param[in]   SaltValue      Points to the salt buffer
  @param[in]   SaltSize       Size of the salt buffer
  @param[in]   InputData      Points to the input data
  @param[in]   InputDataSize  Size of the input data
  @param[out]  OutputData     Points to the output data

  @retval      TRUE           Decrypt the data successfully.
  @retval      FALSE          Failed to decrypt the data.

**/
BOOLEAN
EFIAPI
PasswordLibDecrypt(
  IN   UINT32              SymType,
  IN   VOID                *Password,
  IN   UINTN               PasswordSize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  IN   VOID                *InputData,
  IN   UINTN               InputDataSize,
  OUT  VOID                *OutputData
  );

#endif