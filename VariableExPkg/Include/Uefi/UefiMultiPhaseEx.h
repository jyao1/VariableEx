/** @file

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __UEFI_MULTIPHASE_EX_H__
#define __UEFI_MULTIPHASE_EX_H__

//
// UEFI specification extension for Variable Attribute.
//
#define EFI_VARIABLE_PASSWORD_AUTHENTICATED      0x00000080
#define EFI_VARIABLE_PASSWORD_PROTECTED          0x00000100

//
// UEFI specification extension for SetVariable() input data.
//
#define EFI_VARIABLE_PASSWORD_TYPE_ASCII    1
#define EFI_VARIABLE_PASSWORD_TYPE_UNICODE  2
typedef struct {
  UINT32                      PasswordType;
  UINT32                      PasswordSize;
  //  union {
  //    CHAR8                       AsciiData[PasswordSize];
  //    CHAR16                      UnicodeData[PasswordSize/2];
  //  } Data;
} EFI_VARIABLE_PASSWORD_DATA;

//
// If EFI_VARIABLE_PASSWORD_AUTHENTICATED or EFI_VARIABLE_PASSWORD_PROTECTED is set,
// the input data for SetVariable is:
// +----------------------------+
// | EFI_VARIABLE_PASSWORD_DATA  |
// | (include Password Data)     |
// +----------------------------+
// |   User Data                 |
// +----------------------------+
//

//
// If EFI_VARIABLE_PASSWORD_PROTECTED is set,
// the input data for GetVariable is:
// +----------------------------+
// | EFI_VARIABLE_PASSWORD_DATA  |
// | (include Password Data)     |
// +----------------------------+
// |   Dummy Buffer              |
// +----------------------------+
//

#endif