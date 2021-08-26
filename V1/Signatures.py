from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public = private.public_key()
    pu_ser = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, pu_ser


def sign(message, private):
    message = bytes(str(message),'utf-8')
    signature = private.sign(message,
                             padding.PSS(
                                 mgf=padding.MGF1(hashes.SHA384()),
                                 salt_length=padding.PSS.MAX_LENGTH
                             ), hashes.SHA384())
    return signature


def verify(message, sig, public):
    loaded_pu = serialization.load_pem_public_key(public,backend= default_backend())
    message = bytes(str(message),'utf-8')
    try:
        loaded_pu.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
        return True
    except InvalidSignature:
        return False
    except: 
        print("Error executing public key verify")
        return False



if __name__ == '__main__':
    pk, puk = generate_keys()
    print(pk, '\n', puk)
    message = "This is the secret msg"
    sig = sign(message, pk)
    print(sig)
    correct = verify(message, sig, puk)
    print(correct)
    if correct:
        print("Success! Good sig")
    else:
        print("Error! signature bad")

    pk2,puk2 = generate_keys()

    sig2 = sign(message,pk2)
    correct = verify(message,sig2,puk)
    if correct:
        print("Error! bad signature checks out")
    else:
        print("Success! bad sign detected")

    badmess = message + 'Q'
    correct = verify(badmess,sig,puk)
    if correct:
        print("Error! Tampered message checks out")
    else:
        print("Success! Tampering detected")