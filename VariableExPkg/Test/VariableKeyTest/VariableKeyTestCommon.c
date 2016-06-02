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
#include <Protocol/VariableEx.h>

#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

#include "VariableKeyTestCommon.h"

EFI_GUID mVarKeyTestGuid = VAR_KEY_TEST_GUID;

SET_VAR_KEY_TEST_STRUCT  mSetData = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07 }
};

SET_VAR_KEY_TEST_STRUCT  mSetRightData = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

SET_VAR_KEY_TEST_STRUCT  mSetWrongData = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 }
};

DELETE_VAR_KEY_TEST_STRUCT  mDeleteData = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

DELETE_VAR_KEY_TEST_STRUCT  mDeleteWrongData = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

GET_VAR_KEY_TEST_STRUCT  mGetData = {
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

GET_VAR_KEY_PROTECT_TEST_STRUCT  mGetDataInput = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 },
};

GET_VAR_KEY_PROTECT_TEST_STRUCT  mGetWrongDataInput = {
  { EDKII_VARIABLE_KEY_TYPE_RAW, KEY_SIZE },
  { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x39 },
};

/**
  Unit test for EDKII_VARIABLE_KEY_AUTHENTICATED.
  
  @param TestPhase Phase on when test runs
**/
VOID
KeyAuthTest (
  IN TEST_PHASE TestPhase
  )
{
  EFI_STATUS                            Status;
  GET_VAR_KEY_TEST_STRUCT               GetData;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### KeyAuthTest BEGIN #####\n"));

  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 1: Create KEY_AUTH variable\n"));
    Status = TestSetVariableEx (
               VAR_KEY_AUTH_TEST_NAME,
               &mVarKeyTestGuid,
               EFI_VARIABLE_NON_VOLATILE |
                 EFI_VARIABLE_BOOTSERVICE_ACCESS |
                 EFI_VARIABLE_RUNTIME_ACCESS,
               EDKII_VARIABLE_KEY_AUTHENTICATED,
               sizeof(mSetData),
               &mSetData
               );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 2: Update KEY_AUTH variable\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_AUTHENTICATED,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 3: Update KEY_AUTH variable fail due to invalid key\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_AUTHENTICATED,
                       sizeof(mSetWrongData),
                       &mSetWrongData
                       );
    ASSERT(Status == EFI_SECURITY_VIOLATION);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 4: Update KEY_AUTH variable fail due to invalid attributes\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       0,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT(Status == EFI_INVALID_PARAMETER);
  }
  
  DEBUG((EFI_D_INFO, "Test 5: Get KEY_AUTH variable\n"));
  DataSize = sizeof(GetData);
  Status = TestGetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       &Attributes,
                       &AttributesEx,
                       &DataSize,
                       &GetData
                       );
  if (TestPhase != TestPhasePei) {
    ASSERT(Status == EFI_SUCCESS);
  } else {
    ASSERT((Status == EFI_SUCCESS) || (Status == EFI_NOT_FOUND));
  }

  if (Status == EFI_SUCCESS) {
    DEBUG((EFI_D_INFO, "Test 5.1: Get KEY_AUTH variable data correct\n"));
    ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                          EFI_VARIABLE_BOOTSERVICE_ACCESS |
                          EFI_VARIABLE_RUNTIME_ACCESS));
    ASSERT(AttributesEx == EDKII_VARIABLE_KEY_AUTHENTICATED);
    ASSERT(DataSize == sizeof(GetData));
    ASSERT(CompareMem(&GetData, &mGetData, sizeof(GetData)) == 0);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 6: Delete KEY_AUTH variable fail due to invalid key\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       0,
                       EDKII_VARIABLE_KEY_AUTHENTICATED,
                       sizeof(mDeleteWrongData),
                       &mDeleteWrongData
                       );
    ASSERT (Status == EFI_SECURITY_VIOLATION);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 7: Delete KEY_AUTH variable\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       0,
                       EDKII_VARIABLE_KEY_AUTHENTICATED,
                       sizeof(mDeleteData),
                       &mDeleteData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 8: Get KEY_AUTH variable fail after deletion\n"));
    DataSize = sizeof(GetData);
    Status = TestGetVariableEx (
                       VAR_KEY_AUTH_TEST_NAME,
                       &mVarKeyTestGuid,
                       &Attributes,
                       &AttributesEx,
                       &DataSize,
                       &GetData
                       );
    ASSERT(Status == EFI_NOT_FOUND);
  }

  if (TestPhase == TestPhaseDxe) {
    DEBUG((EFI_D_INFO, "Test 9: Set KEY_AUTH variable for PEI test\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_AUTH_PEI_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_AUTHENTICATED,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }

  DEBUG((EFI_D_INFO, "##### KeyAuthTest END #####\n"));
}

/**
  Unit test for EDKII_VARIABLE_KEY_PROTECTED.
  
  @param TestPhase Phase on when test runs
**/
VOID
KeyProtectTest (
  IN TEST_PHASE TestPhase
  )
{
  EFI_STATUS                            Status;
  GET_VAR_KEY_TEST_STRUCT               *GetDataOutput;
  GET_VAR_KEY_PROTECT_TEST_STRUCT       GetDataInput;
  UINTN                                 DataSize;
  UINT32                                Attributes;
  UINT8                                 AttributesEx;

  DEBUG((EFI_D_INFO, "##### KeyProtectTest BEGIN #####\n"));

  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 1: Create KEY_PROTECT variable\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mSetData),
                       &mSetData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 2: Update KEY_PROTECT variable\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 3: Update KEY_PROTECT variable fail due to invalid key\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mSetWrongData),
                       &mSetWrongData
                       );
    ASSERT(Status == EFI_SECURITY_VIOLATION);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 4: Update KEY_PROTECT variable fail due to invalid attributes\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       0,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT(Status == EFI_INVALID_PARAMETER);
  }
  
  DEBUG((EFI_D_INFO, "Test 5: Get KEY_PROTECT variable\n"));
  CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
  DataSize = sizeof(GetDataInput);
  AttributesEx = EDKII_VARIABLE_KEY_PROTECTED;
  Status = TestGetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       &Attributes,
                       &AttributesEx,
                       &DataSize,
                       &GetDataInput
                       );
  if (TestPhase != TestPhasePei) {
    ASSERT(Status == EFI_SUCCESS);
  } else {
    ASSERT((Status == EFI_SUCCESS) || (Status == EFI_NOT_FOUND));
  }

  if (Status == EFI_SUCCESS) {
    DEBUG((EFI_D_INFO, "Test 5.1: Get KEY_PROTECT variable data correct\n"));
    GetDataOutput = (GET_VAR_KEY_TEST_STRUCT *)&GetDataInput;
    ASSERT(Attributes == (EFI_VARIABLE_NON_VOLATILE |
                          EFI_VARIABLE_BOOTSERVICE_ACCESS |
                          EFI_VARIABLE_RUNTIME_ACCESS));
    ASSERT(AttributesEx == EDKII_VARIABLE_KEY_PROTECTED);
    ASSERT(DataSize == sizeof(*GetDataOutput));
    ASSERT(CompareMem(GetDataOutput, &mGetData, sizeof(*GetDataOutput)) == 0);

    DEBUG((EFI_D_INFO, "Test 5.2: Get KEY_PROTECT variable data with wrong key\n"));
    CopyMem(&GetDataInput, &mGetWrongDataInput, sizeof(GetDataInput));
    DataSize = sizeof(GetDataInput);
    AttributesEx = EDKII_VARIABLE_KEY_PROTECTED;
    Status = TestGetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       &Attributes,
                       &AttributesEx,
                       &DataSize,
                       &GetDataInput
                       );
    ASSERT(Status == EFI_SECURITY_VIOLATION);
  }

  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 6: Delete KEY_PROTECT variable fail due to invalid key\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       0,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mDeleteWrongData),
                       &mDeleteWrongData
                       );
    ASSERT (Status == EFI_SECURITY_VIOLATION);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 7: Delete KEY_PROTECT variable\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       0,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mDeleteData),
                       &mDeleteData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }
  
  if (TestPhase != TestPhasePei) {
    DEBUG((EFI_D_INFO, "Test 8: Get KEY_PROTECT variable fail after deletion\n"));
    CopyMem(&GetDataInput, &mGetDataInput, sizeof(GetDataInput));
    DataSize = sizeof(GetDataInput);
    AttributesEx = EDKII_VARIABLE_KEY_PROTECTED;
    Status = TestGetVariableEx (
                       VAR_KEY_PROTECT_TEST_NAME,
                       &mVarKeyTestGuid,
                       &Attributes,
                       &AttributesEx,
                       &DataSize,
                       &GetDataInput
                       );
    ASSERT(Status == EFI_NOT_FOUND);
  }

  if (TestPhase == TestPhaseDxe) {
    DEBUG((EFI_D_INFO, "Test 9: Set KEY_PROTECT variable for PEI test\n"));
    Status = TestSetVariableEx (
                       VAR_KEY_PROTECT_PEI_TEST_NAME,
                       &mVarKeyTestGuid,
                       EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                       EDKII_VARIABLE_KEY_PROTECTED,
                       sizeof(mSetRightData),
                       &mSetRightData
                       );
    ASSERT (Status == EFI_SUCCESS);
  }

  DEBUG((EFI_D_INFO, "##### KeyProtectTest END #####\n"));
}

