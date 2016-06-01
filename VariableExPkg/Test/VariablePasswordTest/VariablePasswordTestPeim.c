/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <PiPei.h>
#include <Ppi/ReadOnlyVariable2Ex.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/PeiServicesLib.h>

#include "VariablePasswordTestCommon.h"

EFI_GUID mVarPasswordTestGuid = VAR_PASSWORD_TEST_GUID;

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
  EDKII_PEI_READ_ONLY_VARIABLE2_EX_PPI  *VariablePpi;
  EFI_STATUS                            Status;
  GET_VAR_PASSWORD_TEST_STRUCT          GetData;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### PasswordAuthTest BEGIN #####\n"));

  Status = PeiServicesLocatePpi(&gEdkiiPeiReadOnlyVariable2ExPpiGuid, 0, NULL, (VOID **)&VariablePpi);
  ASSERT_EFI_ERROR(Status);

  DEBUG((EFI_D_INFO, "Test PEI 1: Get PASSWORD_AUTH variable\n"));
  DataSize = sizeof(GetData);
  Status = VariablePpi->GetVariableEx (
                          VariablePpi,
                          VAR_PASSWORD_AUTH_PEI_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetData
                          );
  ASSERT((Status == EFI_SUCCESS) || (Status == EFI_NOT_FOUND));

  if (Status == EFI_SUCCESS) {
    DEBUG((EFI_D_INFO, "Test PEI 1.1: Get PASSWORD_AUTH variable data correct\n"));
    ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                          EFI_VARIABLE_BOOTSERVICE_ACCESS |
                          EFI_VARIABLE_RUNTIME_ACCESS));
    ASSERT(AttributesEx == EDKII_VARIABLE_PASSWORD_AUTHENTICATED);
    ASSERT(DataSize == sizeof(GetData));
    ASSERT(CompareMem(&GetData, &mGetData, sizeof(GetData)) == 0);
  }

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
  EDKII_PEI_READ_ONLY_VARIABLE2_EX_PPI  *VariablePpi;
  EFI_STATUS                            Status;
  GET_VAR_PASSWORD_TEST_STRUCT          *GetDataOutput;
  GET_VAR_PASSWORD_PROTECT_TEST_STRUCT  GetDataInput;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### PasswordProtectTest BEGIN #####\n"));

  Status = PeiServicesLocatePpi(&gEdkiiPeiReadOnlyVariable2ExPpiGuid, 0, NULL, (VOID **)&VariablePpi);
  ASSERT_EFI_ERROR(Status);

  DEBUG((EFI_D_INFO, "Test PEI 1: Get PASSWORD_PROTECT variable\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  AttributesEx = EDKII_VARIABLE_PASSWORD_PROTECTED;
  Status = VariablePpi->GetVariableEx (
                          VariablePpi,
                          VAR_PASSWORD_PROTECT_PEI_TEST_NAME,
                          &mVarPasswordTestGuid,
                          &Attributes,
                          &AttributesEx,
                          &DataSize,
                          &GetDataInput
                          );
  ASSERT((Status == EFI_SUCCESS) || (Status == EFI_NOT_FOUND));

  if (Status == EFI_SUCCESS) {
    DEBUG((EFI_D_INFO, "Test PEI 1.1: Get PASSWORD_PROTECT variable data correct\n"));
    GetDataOutput = (GET_VAR_PASSWORD_TEST_STRUCT *)&GetDataInput;
    ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                          EFI_VARIABLE_BOOTSERVICE_ACCESS |
                          EFI_VARIABLE_RUNTIME_ACCESS));
    ASSERT(AttributesEx == EDKII_VARIABLE_PASSWORD_PROTECTED);
    ASSERT(DataSize == sizeof(*GetDataOutput));
    ASSERT(CompareMem(GetDataOutput, &mGetData, sizeof(*GetDataOutput)) == 0);

    DEBUG((EFI_D_INFO, "Test PEI 1.2: Get PASSWORD_PROTECT variable data with wrong password\n"));
    CopyMem(&GetDataInput, &mGetWrongDataInput, sizeof(GetDataInput));
    DataSize = sizeof(GetDataInput);
    AttributesEx = EDKII_VARIABLE_PASSWORD_PROTECTED;
    Status = VariablePpi->GetVariableEx (
                            VariablePpi,
                            VAR_PASSWORD_PROTECT_PEI_TEST_NAME,
                            &mVarPasswordTestGuid,
                            &Attributes,
                            &AttributesEx,
                            &DataSize,
                            &GetDataInput
                            );
    ASSERT(Status == EFI_SECURITY_VIOLATION);
  }

  DEBUG((EFI_D_INFO, "##### PasswordProtectTest END #####\n"));
}

/**
  Test variable services.

  @param  FileHandle   Handle of the file being invoked.
                       Type EFI_PEI_FILE_HANDLE is defined in FfsFindNextFile().
  @param  PeiServices  General purpose services available to every PEIM.

  @retval EFI_SUCCESS  If the interface could be successfully installed
  @retval Others       Returned from PeiServicesInstallPpi()
**/
EFI_STATUS
EFIAPI
PeimMain(
  IN       EFI_PEI_FILE_HANDLE       FileHandle,
  IN CONST EFI_PEI_SERVICES          **PeiServices
  )
{
  PasswordAuthTest();

  PasswordProtectTest();

  return EFI_SUCCESS;
}