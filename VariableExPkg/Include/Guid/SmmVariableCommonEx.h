/** @file
  The file defined some common structures used for communicating between SMM variable module and SMM variable wrapper module.

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _SMM_VARIABLE_COMMON_EX_H_
#define _SMM_VARIABLE_COMMON_EX_H_

#include <Guid/SmmVariableCommon.h>

//
// The payload for this function is SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_EX.
//
#define SMM_VARIABLE_FUNCTION_GET_VARIABLE_EX            81
//
// The payload for this function is SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_EX.
//
#define SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME_EX  82
//
// The payload for this function is SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_EX.
//
#define SMM_VARIABLE_FUNCTION_SET_VARIABLE_EX            83

///
/// This structure is used to communicate with SMI handler by SetVariableEx and GetVariableEx.
///
typedef struct {
  EFI_GUID    Guid;
  UINTN       DataSize;
  UINTN       NameSize;
  UINT32      Attributes;
  UINT8       AttributesEx;
  UINT8       Reserved[3];
  CHAR16      Name[1];
} SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_EX;

///
/// This structure is used to communicate with SMI handler by GetNextVariableNameEx.
///
typedef struct {
  EFI_GUID    Guid;
  UINTN       NameSize;     // Return name buffer size
  UINT32      Attributes;
  UINT8       AttributesEx;
  UINT8       Reserved[3];
  CHAR16      Name[1];
} SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_EX;

#endif // _SMM_VARIABLE_COMMON_EX_H_
