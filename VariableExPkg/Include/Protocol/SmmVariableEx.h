/** @file
  EDKII SMM Variable Ex Protocol is related to EDK II-specific implementation of variables
  and intended for use as a means to store data in the EFI SMM environment.

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#ifndef __EDKII_SMM_VARIABLE_EX_H__
#define __EDKII_SMM_VARIABLE_EX_H__

#include <Protocol/VariableEx.h>

#define EDKII_SMM_VARIABLE_EX_PROTOCOL_GUID \
  { \
    0x996b9441, 0x1375, 0x48fb, { 0x8f, 0x7e, 0xec, 0x22, 0x39, 0xa2, 0x12, 0xa0 } \
  }

typedef struct _EDKII_SMM_VARIABLE_EX_PROTOCOL  EDKII_SMM_VARIABLE_EX_PROTOCOL;

///
/// EFI SMM Variable Protocol is intended for use as a means 
/// to store data in the EFI SMM environment.
///
struct _EDKII_SMM_VARIABLE_EX_PROTOCOL {
  EDKII_GET_VARIABLE_EX            SmmGetVariableEx;
  EDKII_GET_NEXT_VARIABLE_NAME_EX  SmmGetNextVariableNameEx;
  EDKII_SET_VARIABLE_EX            SmmSetVariableEx;
  EFI_QUERY_VARIABLE_INFO          SmmQueryVariableInfo;
};

extern EFI_GUID gEdkiiSmmVariableExProtocolGuid;

#endif  
