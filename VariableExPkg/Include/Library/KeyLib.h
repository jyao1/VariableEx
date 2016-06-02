/** @file

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __KEY_LIB_H__
#define __KEY_LIB_H__

/**
  Generate Salt value.

  @param[in, out]   SaltValue           Points to the salt buffer
  @param[in]        SaltSize            Size of the salt buffer

  @retval      TRUE           Salt is generated.
  @retval      FALSE          Salt is not generated.
**/
BOOLEAN
EFIAPI
KeyLibGenerateSalt(
  IN OUT UINT8  *SaltValue,
  IN UINTN      SaltSize
  );

#define HASH_TYPE_SHA256  0x000B
#define SYM_TYPE_AES      0x0006

#define SHA256_DIGEST_SIZE 32
#define AES_BLOCK_SIZE     16

/**
  Hash the data.

  @param[in]   HashType         Hash type
  @param[in]   Key              Points to the key buffer
  @param[in]   KeySize          Key buffer size
  @param[in]   SaltValue        Points to the salt buffer
  @param[in]   SaltSize         Size of the salt buffer
  @param[out]  KeyHash          Points to the hashed result
  @param[in]   KeyHashSize      Size of the hash buffer

  @retval      TRUE           Hash the data successfully.
  @retval      FALSE          Failed to hash the data.

**/
BOOLEAN
EFIAPI
KeyLibGenerateHash(
  IN   UINT32              HashType,
  IN   VOID                *Key,
  IN   UINTN               KeySize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  OUT  UINT8               *KeyHash,
  IN   UINTN               KeyHashSize
  );

/**
  Encrypt the data.

  InputDataSize must be block size aligned.

  @param[in]   SymType        Symetric Encryption type
  @param[in]   Key            Points to the key buffer
  @param[in]   KeySize        Key buffer size
  @param[in]   SaltValue      Points to the salt buffer
  @param[in]   SaltSize       Size of the salt buffer
  @param[in]   InputData      Points to the input data
  @param[in]   InputDataSize  Size of the input data
  @param[out]  OutputData     Points to the output data
  @param[in]   OutputDataSize Size of the output data

  @retval      TRUE           Encrypt the data successfully.
  @retval      FALSE          Failed to encrypt the data.

**/
BOOLEAN
EFIAPI
KeyLibEncrypt(
  IN   UINT32              SymType,
  IN   VOID                *Key,
  IN   UINTN               KeySize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  IN   VOID                *InputData,
  IN   UINTN               InputDataSize,
  OUT  VOID                *OutputData,
  IN   UINTN               OutputDataSize
  );

/**
  Decrypt the data.

  InputDataSize must be block size aligned.

  @param[in]   SymType        Symetric Encryption type
  @param[in]   Key            Points to the key buffer
  @param[in]   KeySize        Key buffer size
  @param[in]   SaltValue      Points to the salt buffer
  @param[in]   SaltSize       Size of the salt buffer
  @param[in]   InputData      Points to the input data
  @param[in]   InputDataSize  Size of the input data
  @param[out]  OutputData     Points to the output data
  @param[in]   OutputDataSize Size of the output data

  @retval      TRUE           Decrypt the data successfully.
  @retval      FALSE          Failed to decrypt the data.

**/
BOOLEAN
EFIAPI
KeyLibDecrypt(
  IN   UINT32              SymType,
  IN   VOID                *Key,
  IN   UINTN               KeySize,
  IN   UINT8               *SaltValue,
  IN   UINTN               SaltSize,
  IN   VOID                *InputData,
  IN   UINTN               InputDataSize,
  OUT  VOID                *OutputData,
  IN   UINTN               OutputDataSize
  );

#endif