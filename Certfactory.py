def getPrivateKeyForAddr(addr):
    with open(root + "~/CA/pass_privkey") as fp:
        private_key_user = fp.read()

    return private_key_user

def getCertsForAddr():
    with open(root + "~/CA/paas_signed.cert") as fp:
        pub_key_IACA = fp.read()

    return pub_key_IACA

def get
