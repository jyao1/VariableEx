# This package is to demonstrate how to support password based UEFI Variable integrity and confidentiality.

## How to build?
Just build it as a normal EDKII package.

  0) Download EDKII from github https://github.com/tianocore/edk2

  1) Install Visual Studio 2015.

  2) type "edksetup.bat"

  3) type "build -p VariableExPkg\VariableExPkg.dsc -a IA32 -a X64 -t VS2015x86"

## Feature:
1) UEFI specification extension: (VariableExPkg\Include\Uefi\UefiMultiPhaseEx.h)
2 more attributes are added:
EFI_VARIABLE_PASSWORD_AUTHENTICATED attribute is for the password-based integrity.
EFI_VARIABLE_PASSWORD_PROTECTED attribute is for the password-based confidentiality.

2) EDKII Variable Storage extension: (VariableExPkg\Include\Guid\VariableFormatEx.h) 
The variable storage is updated to support the password based HASH and data encryption.

3) Password Lib: (VariableExPkg\Include\Library\PasswordLib.h)
It is a library to provide the generic password management functions.

4) Variable driver: (VariableExPkg\Universal\Variable)
Both Pei variable driver and RuntimeDxe/Smm variable driver are updated to support the
password based authentication and protection.
A platform may use these 2 drivers to replace the variable drivers defined in MdeModulePkg.

5) Unit Test: (VariableExPkg\Test\VariablePasswordTest)
The unit test code for both Pei and RuntimeDxe variable.
It can run on the Nt32 platform.

## Scope:
1) This package only focuses on the secure variable storage management.
This package provides a sample on how to add confidentiality support for UEFI variable.
This package also provides a simpler way to use user password for authentication variable.

2) This package does not focuses on the password management.
This package assumes the caller has a way to get the user password. For example:
The password can be got from user input directly.
The password can be got from an external media, such as USB Key.
The password can be derived from biometrics, such as fingerprint.
Or the password content can be from UEFI variable and decrypted by a root password
as an implementation choice.

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


