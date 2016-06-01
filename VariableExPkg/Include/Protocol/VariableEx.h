/** @file
  Variable Lock Protocol is related to EDK II-specific implementation of variables.

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#ifndef __EDKII_VARIABLE_EX_H__
#define __EDKII_VARIABLE_EX_H__

#include <Uefi.h>

#define EDKII_VARIABLE_EX_PROTOCOL_GUID \
  { \
    0x5e0a3126, 0x1a63, 0x467a, { 0xa2, 0x27, 0xc5, 0x2e, 0xd0, 0xe1, 0xe4, 0xf } \
  }

typedef struct _EDKII_VARIABLE_EX_PROTOCOL  EDKII_VARIABLE_EX_PROTOCOL;

//
// EDKII extension for Variable AttributesEx
//
#define EDKII_VARIABLE_PASSWORD_AUTHENTICATED      0x01
#define EDKII_VARIABLE_PASSWORD_PROTECTED          0x02

//
// EDKII extension
//
#define EDKII_VARIABLE_PASSWORD_TYPE_RAW      0
#define EDKII_VARIABLE_PASSWORD_TYPE_ASCII    1
#define EDKII_VARIABLE_PASSWORD_TYPE_UNICODE  2
typedef struct {
  UINT32                      PasswordType;
  UINT32                      PasswordSize;
  //  union {
  //    UINT8                       RawData[PasswordSize];
  //    CHAR8                       AsciiData[PasswordSize];
  //    CHAR16                      UnicodeData[PasswordSize/2];
  //  } Data;
} EDKII_VARIABLE_PASSWORD_DATA;

//
// If EDKII_VARIABLE_PASSWORD_AUTHENTICATED or EDKII_VARIABLE_PASSWORD_PROTECTED is set,
// the input data for SetVariableEx is:
// +------------------------------+
// | EDKII_VARIABLE_PASSWORD_DATA  |
// | (include Password Data)       |
// +------------------------------+
// |   User Data                   |
// +------------------------------+
//

//
// If EDKII_VARIABLE_PASSWORD_PROTECTED is set,
// the input data for GetVariableEx is:
// +------------------------------+
// | EDKII_VARIABLE_PASSWORD_DATA  |
// | (include Password Data)       |
// +------------------------------+
// |   Dummy Buffer                |
// +------------------------------+
//

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
typedef
EFI_STATUS
(EFIAPI *EDKII_GET_VARIABLE_EX)(
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes,    OPTIONAL
  IN OUT UINT8                       *AttributesEx,
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
  );

/**
  Enumerates the current variable names.

  @param[in, out]  VariableNameSize The size of the VariableName buffer.
  @param[in, out]  VariableName     On input, supplies the last VariableName that was returned
                                    by GetNextVariableName(). On output, returns the Nullterminated
                                    string of the current variable.
  @param[in, out]  VendorGuid       On input, supplies the last VendorGuid that was returned by
                                    GetNextVariableName(). On output, returns the
                                    VendorGuid of the current variable.
  @param[out]      Attributes       If not NULL, a pointer to the memory location to return the
                                    attributes bitmask for the variable.
  @param[out]      AttributesEx     If not NULL, a pointer to the memory location to return the
                                    attributes extension bitmask for the variable.

  @retval EFI_SUCCESS           The function completed successfully.
  @retval EFI_NOT_FOUND         The next variable was not found.
  @retval EFI_BUFFER_TOO_SMALL  The VariableNameSize is too small for the result.
  @retval EFI_INVALID_PARAMETER VariableNameSize is NULL.
  @retval EFI_INVALID_PARAMETER VariableName is NULL.
  @retval EFI_INVALID_PARAMETER VendorGuid is NULL.
  @retval EFI_DEVICE_ERROR      The variable could not be retrieved due to a hardware error.

**/
typedef
EFI_STATUS
(EFIAPI *EDKII_GET_NEXT_VARIABLE_NAME_EX)(
  IN OUT UINTN                    *VariableNameSize,
  IN OUT CHAR16                   *VariableName,
  IN OUT EFI_GUID                 *VendorGuid,
  IN OUT UINT32                   *Attributes,
  IN OUT UINT8                    *AttributesEx
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
typedef
EFI_STATUS
(EFIAPI *EDKII_SET_VARIABLE_EX)(
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINT8                        AttributesEx,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  );

///
/// EDKII Variable Ex Protocol is related to EDK II-specific implementation of variables.
///
struct _EDKII_VARIABLE_EX_PROTOCOL {
  EDKII_GET_VARIABLE_EX            GetVariableEx;
  EDKII_GET_NEXT_VARIABLE_NAME_EX  GetNextVariableNameEx;
  EDKII_SET_VARIABLE_EX            SetVariableEx;
  EFI_QUERY_VARIABLE_INFO          QueryVariableInfo;
};

extern EFI_GUID gEdkiiVariableExProtocolGuid;

#endif  

