from TimeStampLib import TimeStampRequest, parse_tsr, parse_tsq

from pyasn1_modules.rfc2459 import Extensions, Extension
from pyasn1.type import univ, tag
import random as rd

from rfc3161ng import RemoteTimestamper
from pyasn1.codec.der import encoder, decoder

PATH_CERTIFICADO = "certificado.pem"

request = TimeStampRequest(url="http://192.168.88.25/tsp", hash_alg="sha256", data=b"teste")

rt = RemoteTimestamper(url="http://192.168.88.25/tsp", hashname='sha256', timeout=120, include_tsa_certificate=True, c)
	
# Enviando requisicao de carimbo do tempo 
tst = rt.__call__(data=str.encode("ola"), return_tsr=True)

# Salva em arquivo a resposta time-stamping (RFC 3161)
time_stamping_file = open("time_stamping.tsr", "wb")
time_stamping_file.write(encoder.encode(tst))


#tsr, tsq = request.send_query()

#parse_tsq(tsq)
#parse_tsr(tsr, show_signer_info=True)