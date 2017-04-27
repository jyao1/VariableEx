/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

#include <Library/KeyLib.h>

#define DEFAULT_AES_KEY_BIT_SIZE       256
#define DEFAULT_PBKDF2_ITERATION_COUNT 15

/**
  Generate Salt value.

  @param[in, out]   SaltValue           Points to the salt buffer
  @param[in]        SaltSize            Size of the salt buffer

  @retval      TRUE           Salt is generated.
  @retval      FALSE          Salt is not generated.
**/
BOOLEAN
EFIAPI
KeyLibGenerateSalt (
  IN OUT UINT8  *SaltValue,
  IN UINTN      SaltSize
  )
{
  if (SaltValue == NULL) {
    return FALSE;
  }
  RandomSeed(NULL, 0);
  RandomBytes(SaltValue, SaltSize);
  return TRUE;
}

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
  )
{
  BOOLEAN                     Status;
  VOID                        *Hash;

  Status = FALSE;

  if (HashType != HASH_TYPE_SHA256) {
    return FALSE;
  }
  if (KeyHashSize != SHA256_DIGEST_SIZE) {
    return FALSE;
  }

  if ((Key == NULL) || (SaltValue == NULL) || (KeyHash == NULL)) {
    return FALSE;
  }

  Hash = AllocatePool (Sha256GetContextSize ());
  if (Hash == NULL) {
    goto Done;
  }

  Status = Sha256Init(Hash);
  if (!Status) {
    goto Done;
  }

  Status = Sha256Update(Hash, SaltValue, SaltSize);
  if (!Status) {
    goto Done;
  }
  Status = Sha256Update(Hash, Key, KeySize);
  if (!Status) {
    goto Done;
  }

  Status = Sha256Final(Hash, KeyHash);
Done:
  if (Hash != NULL) {
    FreePool (Hash);
  }
  return Status;
}

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
  )
{
  BOOLEAN                     Status;
  UINT8                       KeyBuffer[(DEFAULT_AES_KEY_BIT_SIZE / 8) + AES_BLOCK_SIZE];
  UINT8                       *Ivec;
  VOID                        *AesCtx;

  if (SymType != SYM_TYPE_AES) {
    return FALSE;
  }

  if (((InputDataSize % AES_BLOCK_SIZE) != 0) || ((OutputDataSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }
  if (InputDataSize != OutputDataSize) {
    return FALSE;
  }

  if ((Key == NULL) || (SaltValue == NULL) || (InputData == NULL) || (OutputData == NULL)) {
    return FALSE;
  }
  if ((KeySize > MAX_UINTN) || (SaltSize > MAX_UINTN)) {
    return FALSE;
  }

  Status = Pkcs5HashPassword (
             KeySize,
             Key,
             SaltSize,
             SaltValue,
             DEFAULT_PBKDF2_ITERATION_COUNT,
             SHA256_DIGEST_SIZE,
             sizeof (KeyBuffer),
             KeyBuffer
             );
  if (!Status) {
    return FALSE;
  }

  Ivec = KeyBuffer + (DEFAULT_AES_KEY_BIT_SIZE / 8);

  AesCtx = AllocatePool (AesGetContextSize());
  if (AesCtx == NULL) {
    return FALSE;
  }
  Status = AesInit (AesCtx, KeyBuffer, DEFAULT_AES_KEY_BIT_SIZE);
  if (!Status) {
    goto Done;
  }

  Status = AesCbcEncrypt (
             AesCtx,
             InputData,
             InputDataSize,
             Ivec,
             OutputData
             );

Done:
  if (AesCtx != NULL) {
    FreePool (AesCtx);
  }
  return Status;
}

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
  )
{
  BOOLEAN                     Status;
  UINT8                       KeyBuffer[(DEFAULT_AES_KEY_BIT_SIZE / 8) + AES_BLOCK_SIZE];
  UINT8                       *Ivec;
  VOID                        *AesCtx;

  if (SymType != SYM_TYPE_AES) {
    return FALSE;
  }

  if (((InputDataSize % AES_BLOCK_SIZE) != 0) || ((OutputDataSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }
  if (InputDataSize != OutputDataSize) {
    return FALSE;
  }

  if ((Key == NULL) || (SaltValue == NULL) || (InputData == NULL) || (OutputData == NULL)) {
    return FALSE;
  }
  if ((KeySize > MAX_UINTN) || (SaltSize > MAX_UINTN)) {
    return FALSE;
  }

  Status = Pkcs5HashPassword (
             KeySize,
             Key,
             SaltSize,
             SaltValue,
             DEFAULT_PBKDF2_ITERATION_COUNT,
             SHA256_DIGEST_SIZE,
             sizeof (KeyBuffer),
             KeyBuffer
             );
  if (!Status) {
    return FALSE;
  }

  Ivec = KeyBuffer + (DEFAULT_AES_KEY_BIT_SIZE / 8);

  AesCtx = AllocatePool (AesGetContextSize());
  if (AesCtx == NULL) {
    return FALSE;
  }

  Status = AesInit (AesCtx, KeyBuffer, DEFAULT_AES_KEY_BIT_SIZE);
  if (!Status) {
    goto Done;
  }

  Status = AesCbcDecrypt (AesCtx, InputData, InputDataSize, Ivec, OutputData);

Done:
  if (AesCtx != NULL) {
    FreePool (AesCtx);
  }
  return Status;
}
