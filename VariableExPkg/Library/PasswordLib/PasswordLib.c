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
#include <Library/DebugLib.h>
#include <Library/PasswordLib.h>
#include <Library/BaseCryptLib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define PASSWORD_AES_KEY_BIT_SIZE  256

/**
  Generate Salt value.

  @param[in, out]   SaltValue           Points to the salt buffer
  @param[in]        SaltSize            Size of the salt buffer

**/
VOID
EFIAPI
PasswordLibGenerateSalt (
  IN OUT UINT8  *SaltValue,
  IN UINTN      SaltSize
  )
{
  RandomSeed(NULL, 0);
  RandomBytes(SaltValue, SaltSize);
}

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
  )
{
  BOOLEAN                     Status;
  SHA256_CTX                  Hash;

  if (HashType != PASSWORD_HASH_TYPE_SHA256) {
    return FALSE;
  }

  Status = Sha256Init(&Hash);
  if (!Status) {
    goto Done;
  }

  Status = Sha256Update(&Hash, SaltValue, SaltSize);
  if (!Status) {
    goto Done;
  }
  Status = Sha256Update(&Hash, Password, PasswordSize);
  if (!Status) {
    goto Done;
  }

  Status = Sha256Final(&Hash, PasswordHash);
Done:
  return Status;
}

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
  )
{
  INTN                        Status;
  UINT8                       Key[PASSWORD_AES_KEY_BIT_SIZE / 8];
  AES_KEY                     AesKey;

  if (SymType != PASSWORD_SYM_TYPE_AES) {
    return FALSE;
  }

  if ((InputDataSize % AES_BLOCK_SIZE) != 0) {
    return FALSE;
  }

  Status = PKCS5_PBKDF2_HMAC(
             Password,
             (INT32)PasswordSize,
             SaltValue,
             (INT32)SaltSize,
             16,
             EVP_sha256(),
             sizeof(Key),
             Key
             );
  if (Status == 0) {
    return FALSE;
  }

  Status = AES_set_encrypt_key(Key, PASSWORD_AES_KEY_BIT_SIZE, &AesKey);
  if (Status != 0) {
    return FALSE;
  }

  while (InputDataSize > 0) {
    AES_ecb_encrypt(InputData, OutputData, &AesKey, AES_ENCRYPT);
    InputData = (UINT8 *)InputData + AES_BLOCK_SIZE;
    OutputData = (UINT8 *)OutputData + AES_BLOCK_SIZE;
    InputDataSize -= AES_BLOCK_SIZE;
  }
  
  return TRUE;
}

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
  )
{
  INTN                        Status;
  UINT8                       Key[PASSWORD_AES_KEY_BIT_SIZE / 8];
  AES_KEY                     AesKey;

  if (SymType != PASSWORD_SYM_TYPE_AES) {
    return FALSE;
  }

  if ((InputDataSize % AES_BLOCK_SIZE) != 0) {
    return FALSE;
  }

  Status = PKCS5_PBKDF2_HMAC(
             Password,
             (INT32)PasswordSize,
             SaltValue,
             (INT32)SaltSize,
             16,
             EVP_sha256(),
             sizeof(Key),
             Key
             );
  if (Status == 0) {
    return FALSE;
  }

  Status = AES_set_decrypt_key(Key, PASSWORD_AES_KEY_BIT_SIZE, &AesKey);
  if (Status != 0) {
    return FALSE;
  }

  while (InputDataSize > 0) {
    AES_ecb_encrypt(InputData, OutputData, &AesKey, AES_DECRYPT);
    InputData = (UINT8 *)InputData + AES_BLOCK_SIZE;
    OutputData = (UINT8 *)OutputData + AES_BLOCK_SIZE;
    InputDataSize -= AES_BLOCK_SIZE;
  }

  return TRUE;
}
