from TimeStampLib import TimeStampRequest, parse_tsr, parse_tsq

from pyasn1_modules.rfc2459 import Extensions
from pyasn1.type import tag
import random as rd
from pyasn1.codec.der import encoder, decoder

PATH_CERTIFICADO = "certificado.pem"

request = TimeStampRequest(url="http://192.168.88.25/tsp", data="".join('{:02x}'.format(x) for x in rd.randbytes(32)), \
                           hash_alg="sha256", cert_req=False)

tsr, tsq = request.send_query()

parse_tsq(tsq)
parse_tsr(tsr, show_signer_info=True)