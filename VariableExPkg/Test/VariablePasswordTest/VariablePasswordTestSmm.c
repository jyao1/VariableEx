/** @file

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiSmm.h>
#include <Protocol/SmmVariableEx.h>

#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/SmmServicesTableLib.h>

#include "VariablePasswordTestCommon.h"

EFI_GUID mVarPasswordTestGuid = VAR_PASSWORD_TEST_GUID;

SET_VAR_PASSWORD_TEST_STRUCT  mSetData = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07 }
};

SET_VAR_PASSWORD_TEST_STRUCT  mSetRightData = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

SET_VAR_PASSWORD_TEST_STRUCT  mSetWrongData = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 }
};

DELETE_VAR_PASSWORD_TEST_STRUCT  mDeleteData = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

DELETE_VAR_PASSWORD_TEST_STRUCT  mDeleteWrongData = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

GET_VAR_PASSWORD_TEST_STRUCT  mGetData = {
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  mGetDataInput = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  mGetWrongDataInput = {
  { EDKII_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

/**
  Unit test for EDKII_VARIABLE_PASSWORD_AUTHENTICATED.
**/
VOID
PasswordAuthTest (
  VOID
  )
{
  EDKII_SMM_VARIABLE_EX_PROTOCOL        *SmmVariable;
  EFI_STATUS                            Status;
  GET_VAR_PASSWORD_TEST_STRUCT          GetData;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### PasswordAuthTest BEGIN #####\n"));

  Status = gSmst->SmmLocateProtocol (&gEdkiiSmmVariableExProtocolGuid, NULL, (VOID **)&SmmVariable);
  ASSERT_EFI_ERROR (Status);

  DEBUG((EFI_D_INFO, "Test 1: Create PASSWORD_AUTH variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          EDKII_VARIABLE_PASSWORD_AUTHENTICATED,
                          sizeof(mSetData),
                          &mSetData
                          );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 2: Update PASSWORD_AUTH variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS,
                  EDKII_VARIABLE_PASSWORD_AUTHENTICATED,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 3: Update PASSWORD_AUTH variable fail due to invalid password\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          EDKII_VARIABLE_PASSWORD_AUTHENTICATED,
                          sizeof(mSetWrongData),
                          &mSetWrongData
                          );
  ASSERT(Status == EFI_SECURITY_VIOLATION);

  DEBUG((EFI_D_INFO, "Test 4: Update PASSWORD_AUTH variable fail due to invalid attributes\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          0,
                          sizeof(mSetRightData),
                          &mSetRightData
                          );
  ASSERT(Status == EFI_INVALID_PARAMETER);

  DEBUG((EFI_D_INFO, "Test 5: Get PASSWORD_AUTH variable\n"));
  DataSize = sizeof(GetData);
  Status = SmmVariable->SmmGetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetData
                          );
  ASSERT(Status == EFI_SUCCESS);

  DEBUG((EFI_D_INFO, "Test 5.1: Get PASSWORD_AUTH variable data correct\n"));
  ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS));
  ASSERT(AttributesEx == EDKII_VARIABLE_PASSWORD_AUTHENTICATED);
  ASSERT(DataSize == sizeof(GetData));
  ASSERT(CompareMem(&GetData, &mGetData, sizeof(GetData)) == 0);
  
  DEBUG((EFI_D_INFO, "Test 6: Delete PASSWORD_AUTH variable fail due to invalid password\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          0,
                          EDKII_VARIABLE_PASSWORD_AUTHENTICATED,
                          sizeof(mDeleteWrongData),
                          &mDeleteWrongData
                          );
  ASSERT (Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 7: Delete PASSWORD_AUTH variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          0,
                          EDKII_VARIABLE_PASSWORD_AUTHENTICATED,
                          sizeof(mDeleteData),
                          &mDeleteData
                          );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 8: Get PASSWORD_AUTH variable fail after deletion\n"));
  DataSize = sizeof(GetData);
  Status = SmmVariable->SmmGetVariableEx (
                          VAR_PASSWORD_AUTH_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetData
                          );
  ASSERT(Status == EFI_NOT_FOUND);

  DEBUG((EFI_D_INFO, "##### PasswordAuthTest END #####\n"));
}

/**
  Unit test for EDKII_VARIABLE_PASSWORD_PROTECTED.
**/
VOID
PasswordProtectTest (
  VOID
  )
{
  EDKII_SMM_VARIABLE_EX_PROTOCOL        *SmmVariable;
  EFI_STATUS                            Status;
  GET_VAR_PASSWORD_TEST_STRUCT          *GetDataOutput;
  GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  GetDataInput;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### PasswordProtectTest BEGIN #####\n"));

  Status = gSmst->SmmLocateProtocol (&gEdkiiSmmVariableExProtocolGuid, NULL, (VOID **)&SmmVariable);
  ASSERT_EFI_ERROR (Status);

  DEBUG((EFI_D_INFO, "Test 1: Create PASSWORD_PROTECT variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          EDKII_VARIABLE_PASSWORD_PROTECTED,
                          sizeof(mSetData),
                          &mSetData
                          );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 2: Update PASSWORD_PROTECT variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          EDKII_VARIABLE_PASSWORD_PROTECTED,
                          sizeof(mSetRightData),
                          &mSetRightData
                          );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 3: Update PASSWORD_PROTECT variable fail due to invalid password\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          EDKII_VARIABLE_PASSWORD_PROTECTED,
                          sizeof(mSetWrongData),
                          &mSetWrongData
                          );
  ASSERT(Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 4: Update PASSWORD_PROTECT variable fail due to invalid attributes\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS,
                          0,
                          sizeof(mSetRightData),
                          &mSetRightData
                          );
  ASSERT(Status == EFI_INVALID_PARAMETER);
  
  DEBUG((EFI_D_INFO, "Test 5: Get PASSWORD_PROTECT variable\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  AttributesEx = EDKII_VARIABLE_PASSWORD_PROTECTED;
  Status = SmmVariable->SmmGetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetDataInput
                          );
  ASSERT(Status == EFI_SUCCESS);

  DEBUG((EFI_D_INFO, "Test 5.1: Get PASSWORD_PROTECT variable data correct\n"));
  GetDataOutput = (GET_VAR_PASSWORD_TEST_STRUCT *)&GetDataInput;
  ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS));
  ASSERT(AttributesEx == EDKII_VARIABLE_PASSWORD_PROTECTED);
  ASSERT(DataSize == sizeof(*GetDataOutput));
  ASSERT(CompareMem(GetDataOutput, &mGetData, sizeof(*GetDataOutput)) == 0);
  
  DEBUG((EFI_D_INFO, "Test 5.2: Get PASSWORD_PROTECT variable data with wrong password\n"));
  CopyMem(&GetDataInput, &mGetWrongDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  AttributesEx = EDKII_VARIABLE_PASSWORD_PROTECTED;
  Status = SmmVariable->SmmGetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetDataInput
                          );
  ASSERT(Status == EFI_SECURITY_VIOLATION);

  DEBUG((EFI_D_INFO, "Test 6: Delete PASSWORD_PROTECT variable fail due to invalid password\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          0,
                          EDKII_VARIABLE_PASSWORD_PROTECTED,
                          sizeof(mDeleteWrongData),
                          &mDeleteWrongData
                          );
  ASSERT (Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 7: Delete PASSWORD_PROTECT variable\n"));
  Status = SmmVariable->SmmSetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          0,
                          EDKII_VARIABLE_PASSWORD_PROTECTED,
                          sizeof(mDeleteData),
                          &mDeleteData
                          );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 8: Get PASSWORD_PROTECT variable fail after deletion\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  AttributesEx = EDKII_VARIABLE_PASSWORD_PROTECTED;
  Status = SmmVariable->SmmGetVariableEx (
                          VAR_PASSWORD_PROTECT_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetDataInput
                          );
  ASSERT(Status == EFI_NOT_FOUND);

  DEBUG((EFI_D_INFO, "##### PasswordProtectTest END #####\n"));
}

/**
  The user Entry Point for Test.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
SmmMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  PasswordAuthTest();

  PasswordProtectTest();

  return EFI_SUCCESS;
}