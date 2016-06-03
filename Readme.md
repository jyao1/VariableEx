# This package is to demonstrate how to support key based UEFI Variable integrity and confidentiality.

## How to build?
Just build it as a normal EDKII package.

  0) Download EDKII from github https://github.com/tianocore/edk2

  1) Install Visual Studio 2015.

  2) type "edksetup.bat"

  3) type "build -p VariableExPkg\VariableExPkg.dsc -a IA32 -a X64 -t VS2015x86"

## Feature:
1) EDKII Variable Ppi/Protocol extension: (VariableExPkg\Include\Ppi\ReadOnlyVariable2Ex.h,
VariableExPkg\Include\Protocol\VariableEx.h, VariableExPkg\Include\Protocol\SmmVariableEx.h)
Below attributes extension is added:
  EDKII_VARIABLE_KEY_AUTHENTICATED is for the key-based integrity.
  EDKII_VARIABLE_KEY_ENCRYPTED is for the key-based confidentiality.

2) EDKII Variable Storage extension: (VariableExPkg\Include\Guid\VariableFormatEx.h) 
The variable storage is updated to support the key based HASH and data encryption.

3) Key Lib: (VariableExPkg\Include\Library\KeyLib.h)
It is a library to provide the generic key-based crypto functions.

4) Variable driver: (VariableExPkg\Universal\Variable)
Both Pei variable driver and RuntimeDxe/Smm variable driver are updated to support the
key based authentication and encryption.
A platform may use these 2 drivers to replace the variable drivers defined in MdeModulePkg.

5) Unit Test: (VariableExPkg\Test\VariableKeyTest)
The unit test code for both Pei and RuntimeDxe variable.
It can run on the Nt32 platform.

## Scope:
1) This package only focuses on the secure variable storage management.
This package provides a sample on how to add confidentiality support for UEFI variable.
This package also provides a simpler way to use user key for authentication variable.

2) This package does not focuses on the key management.
This package assumes the caller has a way to get the user key. For example:
The key can be got from user input password directly.
The key can be got from the other media, such as USB disk, TPM, or co-processor.
The key can be derived from biometrics, such as fingerprint.
Or the key content can be from UEFI variable and decrypted by a root key
as an implementation choice.

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


