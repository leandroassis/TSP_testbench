from rfc3161ng import *
import rfc3161ng

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2459

import random as rd
import hashlib
import requests
import base64

class TimeStampRequest():
    def __init__(self, data=None, hash_alg : str = "sha256", version : str ="v1", request_policy : bool =False, \
                 nonce : int =None, cert_req : bool =True, default_hash_oid : tuple = (1, 3, 6, 1, 5, 5, 7, 3, 3),\
                 url : str = 'http://192.168.88.25/tsq', username=None, passwd=None, \
                 pub_cert_key : bytearray = None ,*extensions):
        
        self.version = version
        self.message_imprint = rfc3161ng.MessageImprint()
        self.req_policy = request_policy
        self.nonce = rd.randint(-2**64, 2**64-1) if nonce is None else nonce
        self.tsa_cert_req = cert_req

        if len(extensions) <= 1:
            self.extensions = extensions

        self.hashname = hash_alg
        self.data = data

        self.random_hash_oid = default_hash_oid

        self.url = url
        self.username = username
        self.password = passwd
        self.timeout = 150

        self.certificate = pub_cert_key

    def send_query(self, digest=None):
        tsq = self.create_request(digest)

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

        tsr = decode_timestamp_response(response.content)
        self.check_response(tsr, digest, nonce=self.nonce)
        return encoder.encode(tsr)

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

    def create_request(self, digest=None):
        algorithm_identifier = rfc2459.AlgorithmIdentifier()
        algorithm_identifier.setComponentByPosition(0, self.get_hash_oid(self.hashname))
        
        hashobj = hashlib.new("sha256" if 'id_' + self.hashname not in rfc3161ng.__dict__.keys() else self.hashname)

        if self.data is not None:
            if not isinstance(self.data, bytes):
                self.data = self.data.encode()
            hashobj.update(self.data)
            digest =  hashobj.digest()
        elif digest:
            # verifica se o tamanho do hash passado é compatível com o algoritmo
            assert len(digest) == hashobj.digest_size, 'digest length is wrong %s != %s' % (len(digest), hashobj.digest_size)
            #pass
        
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
            tsq.setComponentByPosition(2, rfc3161ng.types.TSAPolicyId(self.req_policy))
        
        # criando campo nonce
        tsq.setComponentByPosition(3, int(self.nonce))

        # criando campo cert_req
        tsq.setComponentByPosition(4, self.tsa_cert_req)
        return tsq
    
    def get_hash_oid(self, hash_alg : str):
        '''
            id_kp_timeStamping = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 3, 8))
            id_sha1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))
            id_sha256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 1))
            id_sha384 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 2))
            id_sha512 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 3))
            id_ct_TSTInfo = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
        '''

        if 'id_' + hash_alg not in rfc3161ng.__dict__.keys():
            return univ.ObjectIdentifier(self.random_hash_oid)
        
        return rfc3161ng.__dict__['id_' + hash_alg]

def parse_tsr(tsr : bytearray):

    tspObj = TimeStampResp.load(encoder.encode(tsr))

    print("Status Infos")
    print ('Status: ', tspObj['status']['status'].native)
    print('FailureInfo: ', tspObj['status']['failInfo'].native)
    print('StatusString: ', tspObj['status']['statusString'].native)

    '''
	# Recupera obj TstInfo
	timeStampToken = tspObj['time_stamp_token']
	content = timeStampToken['content']
	encapContentInfo = content['encap_content_info']
	tstInfo = encapContentInfo['content'].parsed

	# Mostra algumas informações de TstInfo
	print('Generation_time:', tstInfo['gen_time'].native)
	print('Policy:', tstInfo['policy'].native)
	print('Serial_number:', tstInfo['serial_number'].native)
	print('Nonce:', tstInfo['nonce'].native)
	print('Tem extensions? ', True if tstInfo['extensions'].native != None else "False")
	print('Hash_algorithm:', tstInfo['message_imprint']['hash_algorithm']['algorithm'].native)
	
	print('Tsa:')
	tsaOrderedDict = tstInfo['tsa'].native
	for key in tsaOrderedDict:
		print("     ", key, ": ", tsaOrderedDict[key])
    '''
	
