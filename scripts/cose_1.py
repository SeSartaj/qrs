from pycose.messages import Mac0Message
from pycose.keys.symmetric import SymmetricKey
from pycose.algorithms import HMAC256

key = SymmetricKey.generate_key(16)

msg = Mac0Message(
    phdr = {1: HMAC256},
    payload = b'Hello COSE'
)

msg.key = key

encoded = msg.encode()

print(encoded)