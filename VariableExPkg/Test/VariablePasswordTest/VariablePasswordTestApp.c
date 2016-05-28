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
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Uefi/UefiMultiPhaseEx.h>

#include "VariablePasswordTestCommon.h"

EFI_GUID mVarPasswordTestGuid = VAR_PASSWORD_TEST_GUID;

SET_VAR_PASSWORD_TEST_STRUCT  mSetData = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07 }
};

SET_VAR_PASSWORD_TEST_STRUCT  mSetRightData = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

SET_VAR_PASSWORD_TEST_STRUCT  mSetWrongData = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 }
};

DELETE_VAR_PASSWORD_TEST_STRUCT  mDeleteData = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

DELETE_VAR_PASSWORD_TEST_STRUCT  mDeleteWrongData = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

GET_VAR_PASSWORD_TEST_STRUCT  mGetData = {
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  mGetDataInput = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  mGetWrongDataInput = {
  { EFI_VARIABLE_PASSWORD_TYPE_ASCII, PASSWORD_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

/**
  Unit test for EFI_VARIABLE_PASSWORD_AUTHENTICATED.
**/
VOID
PasswordAuthTest (
  VOID
  )
{
  EFI_STATUS                    Status;
  GET_VAR_PASSWORD_TEST_STRUCT  GetData;
  UINTN                         DataSize;
  UINT32                        Attributes;

  DEBUG((EFI_D_INFO, "##### PasswordAuthTest BEGIN #####\n"));

  DEBUG((EFI_D_INFO, "Test 1: Create PASSWORD_AUTH variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_AUTHENTICATED,
                  sizeof(mSetData),
                  &mSetData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 2: Update PASSWORD_AUTH variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_AUTHENTICATED,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 3: Update PASSWORD_AUTH variable fail due to invalid password\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_AUTHENTICATED,
                  sizeof(mSetWrongData),
                  &mSetWrongData
                  );
  ASSERT(Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 4: Update PASSWORD_AUTH variable fail due to invalid attributes\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT(Status == EFI_INVALID_PARAMETER);
  
  DEBUG((EFI_D_INFO, "Test 5: Get PASSWORD_AUTH variable\n"));
  DataSize = sizeof(GetData);
  Status = gRT->GetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  &Attributes,
                  &DataSize,
                  &GetData
                  );
  ASSERT(Status == EFI_SUCCESS);

  DEBUG((EFI_D_INFO, "Test 5.1: Get PASSWORD_AUTH variable data correct\n"));
  ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS |
                        EFI_VARIABLE_PASSWORD_AUTHENTICATED));
  ASSERT(DataSize == sizeof(GetData));
  ASSERT(CompareMem(&GetData, &mGetData, sizeof(GetData)) == 0);
  
  DEBUG((EFI_D_INFO, "Test 6: Delete PASSWORD_AUTH variable fail due to invalid password\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  0,
                  sizeof(mDeleteWrongData),
                  &mDeleteWrongData
                  );
  ASSERT (Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 7: Delete PASSWORD_AUTH variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  0,
                  sizeof(mDeleteData),
                  &mDeleteData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 8: Get PASSWORD_AUTH variable fail after deletion\n"));
  DataSize = sizeof(GetData);
  Status = gRT->GetVariable (
                  VAR_PASSWORD_AUTH_TEST_NAME,
                  &mVarPasswordTestGuid,
                  &Attributes,
                  &DataSize,
                  &GetData
                  );
  ASSERT(Status == EFI_NOT_FOUND);

  DEBUG((EFI_D_INFO, "Test 9: Set PASSWORD_AUTH variable for PEI test\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_AUTH_PEI_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_AUTHENTICATED,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT (Status == EFI_SUCCESS);

  DEBUG((EFI_D_INFO, "##### PasswordAuthTest END #####\n"));
}

/**
  Unit test for EFI_VARIABLE_PASSWORD_PROTECTED.
**/
VOID
PasswordProtectTest (
  VOID
  )
{
  EFI_STATUS                            Status;
  GET_VAR_PASSWORD_TEST_STRUCT          *GetDataOutput;
  GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  GetDataInput;
  UINTN                                 DataSize;
  UINT32                                Attributes;

  DEBUG((EFI_D_INFO, "##### PasswordProtectTest BEGIN #####\n"));

  DEBUG((EFI_D_INFO, "Test 1: Create PASSWORD_PROTECT variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_PROTECTED,
                  sizeof(mSetData),
                  &mSetData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 2: Update PASSWORD_PROTECT variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_PROTECTED,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 3: Update PASSWORD_PROTECT variable fail due to invalid password\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_PROTECTED,
                  sizeof(mSetWrongData),
                  &mSetWrongData
                  );
  ASSERT(Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 4: Update PASSWORD_PROTECT variable fail due to invalid attributes\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT(Status == EFI_INVALID_PARAMETER);
  
  DEBUG((EFI_D_INFO, "Test 5: Get PASSWORD_PROTECT variable\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  Attributes = EFI_VARIABLE_PASSWORD_PROTECTED;
  Status = gRT->GetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  &Attributes,
                  &DataSize,
                  &GetDataInput
                  );
  ASSERT(Status == EFI_SUCCESS);

  DEBUG((EFI_D_INFO, "Test 5.1: Get PASSWORD_PROTECT variable data correct\n"));
  GetDataOutput = (GET_VAR_PASSWORD_TEST_STRUCT *)&GetDataInput;
  ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                        EFI_VARIABLE_RUNTIME_ACCESS |
                        EFI_VARIABLE_PASSWORD_PROTECTED));
  ASSERT(DataSize == sizeof(*GetDataOutput));
  ASSERT(CompareMem(GetDataOutput, &mGetData, sizeof(*GetDataOutput)) == 0);
  
  DEBUG((EFI_D_INFO, "Test 5.2: Get PASSWORD_PRTECTED variable data with wrong password\n"));
  CopyMem(&GetDataInput, &mGetWrongDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  Attributes = EFI_VARIABLE_PASSWORD_PROTECTED;
  Status = gRT->GetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  &Attributes,
                  &DataSize,
                  &GetDataInput
                  );
  ASSERT(Status == EFI_SECURITY_VIOLATION);

  DEBUG((EFI_D_INFO, "Test 6: Delete PASSWORD_PROTECT variable fail due to invalid password\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  0,
                  sizeof(mDeleteWrongData),
                  &mDeleteWrongData
                  );
  ASSERT (Status == EFI_SECURITY_VIOLATION);
  
  DEBUG((EFI_D_INFO, "Test 7: Delete PASSWORD_PROTECT variable\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  0,
                  sizeof(mDeleteData),
                  &mDeleteData
                  );
  ASSERT (Status == EFI_SUCCESS);
  
  DEBUG((EFI_D_INFO, "Test 8: Get PASSWORD_PROTECT variable fail after deletion\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  Status = gRT->GetVariable (
                  VAR_PASSWORD_PROTECT_TEST_NAME,
                  &mVarPasswordTestGuid,
                  &Attributes,
                  &DataSize,
                  &GetDataInput
                  );
  ASSERT(Status == EFI_NOT_FOUND);

  DEBUG((EFI_D_INFO, "Test 9: Set PASSWORD_PROTECT variable for PEI test\n"));
  Status = gRT->SetVariable (
                  VAR_PASSWORD_PROTECT_PEI_TEST_NAME,
                  &mVarPasswordTestGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_PASSWORD_PROTECTED,
                  sizeof(mSetRightData),
                  &mSetRightData
                  );
  ASSERT (Status == EFI_SUCCESS);

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
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  PasswordAuthTest();

  PasswordProtectTest();

  return EFI_SUCCESS;
}