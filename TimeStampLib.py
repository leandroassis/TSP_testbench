from rfc3161ng import *
import rfc3161ng

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2459

import random as rd
import hashlib
import requests
import base64

from asn1crypto import tsp
from asn1crypto.core import Sequence

WIDTH_LINE = 40

class TimeStampRequest():
    def __init__(self, data=None, hash_alg : str = "sha256", version : str ="v1", request_policy : tuple = None, \
                 nonce : int =None, cert_req : bool = None, url : str=None, username=None, passwd=None, \
                 pub_cert_key : bytearray = None, digest=None, extensions : rfc2459.Extensions=None):
        
        self.version = version
        self.message_imprint = rfc3161ng.MessageImprint()
        self.req_policy = univ.ObjectIdentifier(request_policy) if request_policy is not None else None
        self.nonce = rd.randint(-2**64, 2**64-1) if nonce is None else nonce
        self.tsa_cert_req = cert_req

        self.extensions = extensions

        self.hashname = hash_alg
        self.data = data

        self.random_hash_oid = (1, 3, 6, 1, 5, 5, 7, 3, 3)

        self.url = url
        self.username = username
        self.password = passwd
        self.timeout = 150

        self.certificate = pub_cert_key

        self.digest = digest

    def send_query(self):
        tsq = self.create_request()

        binary_request = encode_timestamp_request(tsq)

        headers = {'Content-Type': 'application/timestamp-query'}
        if self.username is not None:
            username = self.username.encode() if not isinstance(self.username, bytes) else self.username
            password = self.password.encode() if not isinstance(self.password, bytes) else self.password
            base64string = base64.standard_b64encode(b'%s:%s' % (username, password))
            if isinstance(base64string, bytes):
                base64string = base64string.decode()
            headers['Authorization'] = "Basic %s" % base64string
        try:
            response = requests.post(
                self.url,
                data=binary_request,
                timeout=self.timeout,
                headers=headers,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise TimestampingError('Unable to send the request to %r' % self.url, exc)
        
        if self.data is not None:
            hashobj = hashlib.new("sha256" if 'id_' + self.hashname not in rfc3161ng.__dict__.keys() else self.hashname)
            hashobj.update(self.data)
            digest =  hashobj.digest()

        tsr = self.decode_timestamp_response(response.content)
        self.check_response(tsr, digest, nonce=self.nonce)
        return tsr, tsq

    def decode_timestamp_response(self, response):
        tsr, substrate = decoder.decode(response, asn1Spec=rfc3161ng.TimeStampResp())
        if substrate:
            raise ValueError('Extra data returned')
        return tsr

    def check_response(self, response, digest, nonce=None):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        if self.certificate:
            return self.check(tst, digest=digest, nonce=nonce)
        return tst

    def check(self, tst, data=None, digest=None, nonce=None):
        return check_timestamp(
            tst,
            digest=digest,
            data=data,
            nonce=nonce,
            certificate=self.certificate,
            hashname=self.hashname,
        )

    def create_request(self):
        algorithm_identifier = rfc2459.AlgorithmIdentifier()
        algorithm_identifier.setComponentByPosition(0, self.get_hash_oid(self.hashname))
        
        hashobj = hashlib.new("sha256" if 'id_' + self.hashname not in rfc3161ng.__dict__.keys() else self.hashname)

        if self.data is not None and self.digest is None:
            if not isinstance(self.data, bytes):
                self.data = self.data.encode()
            hashobj.update(self.data)
            digest =  hashobj.digest()
        elif self.digest is not None:
            digest = self.digest

        
        # criando request
        tsq = rfc3161ng.TimeStampReq()

        # criando campo version
        tsq.setComponentByPosition(0, self.version)

        # criando campo message_imprint
        message_imprint = rfc3161ng.MessageImprint()
        message_imprint.setComponentByPosition(0, algorithm_identifier)
        message_imprint.setComponentByPosition(1, digest)
    
        tsq.setComponentByPosition(1, message_imprint)

        # criando campo req_policy
        if self.req_policy:
            tsq.setComponentByPosition(2, self.req_policy)
        
        # criando campo nonce
        if self.nonce:
            tsq.setComponentByPosition(3, int(self.nonce))

        # criando campo cert_req
        if self.tsa_cert_req:
            tsq.setComponentByPosition(4, self.tsa_cert_req)

        if self.extensions:
            tsq.setComponentByPosition(5, self.extensions)

        return tsq
    
    def get_hash_oid(self, hash_alg : str):
        '''
            id_sha1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))
            id_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
            id_sha384 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 2))
            id_sha512 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))
        '''

        if 'id_' + hash_alg not in rfc3161ng.__dict__.keys():
            return univ.ObjectIdentifier(self.random_hash_oid)
        
        return rfc3161ng.__dict__['id_' + hash_alg]

class TimeStampResponse(Sequence):
    _fields = [
        ('status', tsp.PKIStatusInfo),
    ]

def parse_tsq(tsq):
    print("version: ", tsq['version'])
    print("hash_algorithm: ", tsq['messageImprint']['hashAlgorithm']['algorithm'])
    print("hashed_message: ", ''.join('{:02x}'.format(x) for x in tsq['messageImprint']['hashedMessage']))
    try:
        print("policy: ", tsq['reqPolicy'])
    except:
        print("None")
    print("nonce: ", tsq['nonce'])
    print("cert_req: ", tsq['certReq'])
    print(tsq['extensions'])

def parse_tsr(tsr : bytearray, show_signer_info : bool = False):

    tspObj = TimeStampResponse.load(encoder.encode(tsr))

    print(" Status Infos ".center(WIDTH_LINE, '='), end='\n\n')
    print ('Status: ', tspObj['status']['status'].native)
    print('FailureInfo: ', tspObj['status']['fail_info'].native)
    print('StatusString: ', tspObj['status']['status_string'].native)
    print("="*WIDTH_LINE, end='\n\n')

    print(" Token Infos ".center(WIDTH_LINE, '='))
    # se não existir um token, termina aqui
    if tspObj['status']['status'].native != 'granted':
        print("Não existe um token.")
        print("="*WIDTH_LINE, end='\n\n')
        return None
    
    tspObj = tsp.TimeStampResp.load(encoder.encode(tsr))

    # Recupera obj TstInfo
    timeStampToken = tspObj['time_stamp_token']
    content = timeStampToken['content']
    encapContentInfo = content['encap_content_info']
    tstInfo = encapContentInfo['content'].parsed

    # Mostra algumas informações de TstInfo
    print('Version:', tstInfo['version'].native)
    print('Generation_time:', tstInfo['gen_time'].native)
    print('Policy:', tstInfo['policy'].native)
    print('Serial_number:', tstInfo['serial_number'].native)
    print('Nonce:', tstInfo['nonce'].native)
    print('Hash_algorithm:', tstInfo['message_imprint']['hash_algorithm']['algorithm'].native)
    print('Hashed_message:', ''.join('{:02x}'.format(x) for x in tstInfo['message_imprint']['hashed_message'].native))
    print('Accuracy:', tstInfo['accuracy'].native)
    print('Ordering:', tstInfo['ordering'].native)
    
    print('Tsa:')
    tsaOrderedDict = tstInfo['tsa'].native
    for key in tsaOrderedDict:
        print("     ", key, ": ", tsaOrderedDict[key])

    if tstInfo['extensions'].native != None:
        print('Extensions:')
        for extensionsOrderedDict in tstInfo['extensions'].native:
            for key in extensionsOrderedDict:
                print("     ", key, ": ", extensionsOrderedDict[key])
    
    signer_infos = content['signer_infos']
    certificates = content['certificates']
                
    if show_signer_info:
        print("\nSignerInfo: ")
        for signer_info in signer_infos:
            print("     ", "Version: ", signer_info['version'].native)
            print("     ", "Sid: ", signer_info['sid'].native)
            print("     ", "Digest_algorithm: ", signer_info['digest_algorithm'].native)
            print("     ", "Signature_algorithm: ", signer_info['signature_algorithm'].native)
            print("     ", "Signature: ", signer_info['signature'].native)
            print("     ", "Signed_attrs: ", signer_info['signed_attrs'].native)
            print("     ", "Unsigned_attrs: ", signer_info['unsigned_attrs'].native)

    if certificates:
        print("\nCertificate: ")
        for certificate in certificates:
            print("     ", certificate.native)
            

    print("="*WIDTH_LINE, end='\n\n')
