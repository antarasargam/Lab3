def getPrivateKeyForAddr():
    with open("/root/antaraprivateclient") as fp:
        private_key_user = fp.read()
    return private_key_user

def getCertsForAddr():
    with open("/root/Downloads/paas_signed.cert") as fp:
        pub_key_IACA = fp.read()
    return pub_key_IACA

def getIDCertsForAddr():
    with open("/root/Downloads/client_cert") as fp:
        id_key_IACA = fp.read()
    return id_key_IACA

def getRootCertsForAddr():
    with open("/root/Downloads/root.crt") as fp:
        root_key_IACA = fp.read()
    return root_key_IACA

def getPrivateKeyForAddrServer():
    with open("/root/antaraprivate") as fp:
        private_key_user = fp.read()
    return private_key_user

def getIDCertsForAddrServer():
    with open("/root/Downloads/server_cert") as fp:
        id_key_IACA = fp.read()
    return id_key_IACA
