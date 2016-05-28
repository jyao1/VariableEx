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

#define PASSWORD_AES_KEY_BIT_SIZE       256
#define PASSWORD_PBKDF2_ITERATION_COUNT 15

/**
  Generate Salt value.

  @param[in, out]   SaltValue           Points to the salt buffer
  @param[in]        SaltSize            Size of the salt buffer

  @retval      TRUE           Salt is generated.
  @retval      FALSE          Salt is not generated.
**/
BOOLEAN
EFIAPI
PasswordLibGenerateSalt (
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
  @param[in]   Password         Points to the password buffer
  @param[in]   PasswordSize     Password buffer size
  @param[in]   SaltValue        Points to the salt buffer
  @param[in]   SaltSize         Size of the salt buffer
  @param[out]  PasswordHash     Points to the hashed result
  @param[in]   PasswordHashSize Size of the hash buffer

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
  OUT  UINT8               *PasswordHash,
  IN   UINTN               PasswordHashSize
  )
{
  BOOLEAN                     Status;
  SHA256_CTX                  Hash;

  if (HashType != PASSWORD_HASH_TYPE_SHA256) {
    return FALSE;
  }
  if (PasswordHashSize != SHA256_DIGEST_SIZE) {
    return FALSE;
  }

  if ((Password == NULL) || (SaltValue == NULL) || (PasswordHash == NULL)) {
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
  @param[in]   OutputDataSize Size of the output data

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
  OUT  VOID                *OutputData,
  IN   UINTN               OutputDataSize
  )
{
  INTN                        Status;
  UINT8                       Key[(PASSWORD_AES_KEY_BIT_SIZE / 8) + AES_BLOCK_SIZE];
  UINT8                       *Ivec;
  AES_KEY                     AesKey;

  if (SymType != PASSWORD_SYM_TYPE_AES) {
    return FALSE;
  }

  if (((InputDataSize % AES_BLOCK_SIZE) != 0) || ((OutputDataSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }
  if (InputDataSize != OutputDataSize) {
    return FALSE;
  }

  if ((Password == NULL) || (SaltValue == NULL) || (InputData == NULL) || (OutputData == NULL)) {
    return FALSE;
  }
  if ((PasswordSize > INT_MAX) || (SaltSize > INT_MAX)) {
    return FALSE;
  }

  Status = PKCS5_PBKDF2_HMAC(
             Password,
             (INT32)PasswordSize,
             SaltValue,
             (INT32)SaltSize,
             PASSWORD_PBKDF2_ITERATION_COUNT,
             EVP_sha256(),
             sizeof(Key),
             Key
             );
  if (Status == 0) {
    return FALSE;
  }

  Ivec = Key + (PASSWORD_AES_KEY_BIT_SIZE / 8);

  Status = AES_set_encrypt_key(Key, PASSWORD_AES_KEY_BIT_SIZE, &AesKey);
  if (Status != 0) {
    return FALSE;
  }

  AES_cbc_encrypt(InputData, OutputData, InputDataSize, &AesKey, Ivec, AES_ENCRYPT);

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
  @param[in]   OutputDataSize Size of the output data

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
  OUT  VOID                *OutputData,
  IN   UINTN               OutputDataSize
  )
{
  INTN                        Status;
  UINT8                       Key[(PASSWORD_AES_KEY_BIT_SIZE / 8) + AES_BLOCK_SIZE];
  UINT8                       *Ivec;
  AES_KEY                     AesKey;

  if (SymType != PASSWORD_SYM_TYPE_AES) {
    return FALSE;
  }

  if (((InputDataSize % AES_BLOCK_SIZE) != 0) || ((OutputDataSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }
  if (InputDataSize != OutputDataSize) {
    return FALSE;
  }

  if ((Password == NULL) || (SaltValue == NULL) || (InputData == NULL) || (OutputData == NULL)) {
    return FALSE;
  }
  if ((PasswordSize > INT_MAX) || (SaltSize > INT_MAX)) {
    return FALSE;
  }

  Status = PKCS5_PBKDF2_HMAC(
             Password,
             (INT32)PasswordSize,
             SaltValue,
             (INT32)SaltSize,
             PASSWORD_PBKDF2_ITERATION_COUNT,
             EVP_sha256(),
             sizeof(Key),
             Key
             );
  if (Status == 0) {
    return FALSE;
  }

  Ivec = Key + (PASSWORD_AES_KEY_BIT_SIZE / 8);

  Status = AES_set_decrypt_key(Key, PASSWORD_AES_KEY_BIT_SIZE, &AesKey);
  if (Status != 0) {
    return FALSE;
  }

  AES_cbc_encrypt(InputData, OutputData, InputDataSize, &AesKey, Ivec, AES_DECRYPT);

  return TRUE;
}
