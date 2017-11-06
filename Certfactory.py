def getPrivateKeyForAddr():
    with open("/root/keys/client/sagar.key") as fp:
        private_key_user = fp.read()
    return private_key_user

def getCertsForAddr():
    with open("/root/keys/paas_signed.cert") as fp:
        pub_key_IACA = fp.read()
    return pub_key_IACA

def getIDCertsForAddr():
    with open("/root/keys/client/client_cert") as fp:
        id_key_IACA = fp.read()
    return id_key_IACA

def getRootCertsForAddr():
    with open("/root/keys/root.crt") as fp:
        root_key_IACA = fp.read()
    return root_key_IACA

