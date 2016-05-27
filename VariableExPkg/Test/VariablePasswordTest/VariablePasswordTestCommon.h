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

#define PASSWORD_SIZE 8
#define VAR_SIZE      8
typedef struct {
  EFI_VARIABLE_PASSWORD_DATA  PasswordHeader;
  CHAR8                       AsciiData[PASSWORD_SIZE];
  UINT8                       VarData[VAR_SIZE];
} SET_VAR_PASSWORD_TEST_STRUCT;

typedef struct {
  EFI_VARIABLE_PASSWORD_DATA  PasswordHeader;
  CHAR8                       AsciiData[PASSWORD_SIZE];
} DELETE_VAR_PASSWORD_TEST_STRUCT;

typedef struct {
  UINT8                       VarData[VAR_SIZE];
} GET_VAR_PASSWORD_TEST_STRUCT;

typedef struct {
  EFI_VARIABLE_PASSWORD_DATA  PasswordHeader;
  CHAR8                       AsciiData[PASSWORD_SIZE];
} GET_VAR_PASSWORD_PROTECT_TEST_STRUCT;
;

//
// EFI_VARIABLE_PASSWORD_AUTHENTICATED test
//
#define VAR_PASSWORD_AUTH_TEST_NAME      L"VarPasswordAuthTest"
#define VAR_PASSWORD_AUTH_PEI_TEST_NAME  L"VarPasswordAuthPeiTest"

//
// EFI_VARIABLE_PASSWORD_PROTECTED test
//
#define VAR_PASSWORD_PROTECT_TEST_NAME      L"VarPasswordProtectTest"
#define VAR_PASSWORD_PROTECT_PEI_TEST_NAME  L"VarPasswordProtectPeiTest"

#define VAR_PASSWORD_TEST_GUID   { \
  0xfde5478e, 0xbdb0, 0x4450, { 0xb2, 0xc0, 0x95, 0x74, 0xc6, 0x94, 0x9e, 0xd } \
}

#endif