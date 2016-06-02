/** @file

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _VARIABLE_PASSOWRD_TEST_COMMON_H_
#define _VARIABLE_PASSOWRD_TEST_COMMON_H_

#define KEY_SIZE 8
#define VAR_SIZE      8
typedef struct {
  EDKII_VARIABLE_KEY_DATA     KeyHeader;
  CHAR8                       AsciiData[KEY_SIZE];
  UINT8                       VarData[VAR_SIZE];
} SET_VAR_KEY_TEST_STRUCT;

typedef struct {
  EDKII_VARIABLE_KEY_DATA     KeyHeader;
  CHAR8                       AsciiData[KEY_SIZE];
} DELETE_VAR_KEY_TEST_STRUCT;

typedef struct {
  UINT8                       VarData[VAR_SIZE];
} GET_VAR_KEY_TEST_STRUCT;

typedef struct {
  EDKII_VARIABLE_KEY_DATA     KeyHeader;
  CHAR8                       AsciiData[KEY_SIZE];
} GET_VAR_KEY_PROTECT_TEST_STRUCT;
;

//
// EDKII_VARIABLE_KEY_AUTHENTICATED test
//
#define VAR_KEY_AUTH_TEST_NAME      L"VarKeyAuthTest"
#define VAR_KEY_AUTH_PEI_TEST_NAME  L"VarKeyAuthPeiTest"

//
// EDKII_VARIABLE_KEY_PROTECTED test
//
#define VAR_KEY_PROTECT_TEST_NAME      L"VarKeyProtectTest"
#define VAR_KEY_PROTECT_PEI_TEST_NAME  L"VarKeyProtectPeiTest"

#define VAR_KEY_TEST_GUID   { \
  0xfde5478e, 0xbdb0, 0x4450, { 0xb2, 0xc0, 0x95, 0x74, 0xc6, 0x94, 0x9e, 0xd } \
}

typedef enum {
  TestPhasePei,
  TestPhaseDxe,
  TestPhaseSmm,
} TEST_PHASE;

/**
  Unit test for EDKII_VARIABLE_KEY_AUTHENTICATED.
  
  @param TestPhase Phase on when test runs
**/
VOID
KeyAuthTest (
  IN TEST_PHASE TestPhase
  );

/**
  Unit test for EDKII_VARIABLE_KEY_PROTECTED.

  @param TestPhase Phase on when test runs
**/
VOID
KeyProtectTest (
  IN TEST_PHASE TestPhase
  );

/**
  Returns the value of a variable.

  @param[in]       VariableName  A Null-terminated string that is the name of the vendor's
                                 variable.
  @param[in]       VendorGuid    A unique identifier for the vendor.
  @param[out]      Attributes    If not NULL, a pointer to the memory location to return the
                                 attributes bitmask for the variable.
  @param[out]      AttributesEx  If not NULL, a pointer to the memory location to return the
                                 attributes extension bitmask for the variable.
  @param[in, out]  DataSize      On input, the size in bytes of the return Data buffer.
                                 On output the size of data returned in Data.
  @param[out]      Data          The buffer to return the contents of the variable. May be NULL
                                 with a zero DataSize in order to determine the size buffer needed.

  @retval EFI_SUCCESS            The function completed successfully.
  @retval EFI_NOT_FOUND          The variable was not found.
  @retval EFI_BUFFER_TOO_SMALL   The DataSize is too small for the result.
  @retval EFI_INVALID_PARAMETER  VariableName is NULL.
  @retval EFI_INVALID_PARAMETER  VendorGuid is NULL.
  @retval EFI_INVALID_PARAMETER  DataSize is NULL.
  @retval EFI_INVALID_PARAMETER  The DataSize is not too small and Data is NULL.
  @retval EFI_DEVICE_ERROR       The variable could not be retrieved due to a hardware error.
  @retval EFI_SECURITY_VIOLATION The variable could not be retrieved due to an authentication failure.

**/
EFI_STATUS
EFIAPI
TestGetVariableEx (
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes,    OPTIONAL
  IN OUT UINT8                       *AttributesEx,
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
  );

/**
  Sets the value of a variable.

  @param[in]  VariableName       A Null-terminated string that is the name of the vendor's variable.
                                 Each VariableName is unique for each VendorGuid. VariableName must
                                 contain 1 or more characters. If VariableName is an empty string,
                                 then EFI_INVALID_PARAMETER is returned.
  @param[in]  VendorGuid         A unique identifier for the vendor.
  @param[in]  Attributes         Attributes bitmask to set for the variable.
  @param[in]  AttributesEx       Attributes Extension bitmask to set for the variable.
  @param[in]  DataSize           The size in bytes of the Data buffer. Unless the EFI_VARIABLE_APPEND_WRITE,
                                 EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, or 
                                 EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute is set, a size of zero 
                                 causes the variable to be deleted. When the EFI_VARIABLE_APPEND_WRITE attribute is 
                                 set, then a SetVariable() call with a DataSize of zero will not cause any change to 
                                 the variable value (the timestamp associated with the variable may be updated however 
                                 even if no new data value is provided,see the description of the 
                                 EFI_VARIABLE_AUTHENTICATION_2 descriptor below. In this case the DataSize will not 
                                 be zero since the EFI_VARIABLE_AUTHENTICATION_2 descriptor will be populated). 
  @param[in]  Data               The contents for the variable.

  @retval EFI_SUCCESS            The firmware has successfully stored the variable and its data as
                                 defined by the Attributes.
  @retval EFI_INVALID_PARAMETER  An invalid combination of attribute bits, name, and GUID was supplied, or the
                                 DataSize exceeds the maximum allowed.
  @retval EFI_INVALID_PARAMETER  VariableName is an empty string.
  @retval EFI_OUT_OF_RESOURCES   Not enough storage is available to hold the variable and its data.
  @retval EFI_DEVICE_ERROR       The variable could not be retrieved due to a hardware error.
  @retval EFI_WRITE_PROTECTED    The variable in question is read-only.
  @retval EFI_WRITE_PROTECTED    The variable in question cannot be deleted.
  @retval EFI_SECURITY_VIOLATION The variable could not be written due to EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 
                                 or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACESS being set, but the AuthInfo 
                                 does NOT pass the validation check carried out by the firmware.
  
  @retval EFI_NOT_FOUND          The variable trying to be updated or deleted was not found.

**/
EFI_STATUS
EFIAPI
TestSetVariableEx(
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINT8                        AttributesEx,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  );

#endif