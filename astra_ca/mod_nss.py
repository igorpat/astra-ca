#!/usr/bin/python3

"""Библиотека функций обработки сертификатов NSS"""

import logging
import os
import nss.nss as nss
import nss.error as error
import xmltodict
from base64 import b64encode
import astra_ca.mod_ssl as mod_ssl


logger = logging.getLogger(os.path.basename(__file__))

#db_path = "/etc/pki/pki-tomcat/alias"
db_path = "/etc/pki/astra-ca/nssdb"

def nss_db_init(func):
    """Инициализация базы данных NSS"""
    def wrapper(*args, **kwargs):
        if not nss.nss_is_initialized():
            nss.nss_init(db_path)
            global cert_db
            cert_db = nss.get_default_certdb()
        return func(*args, **kwargs)
    return wrapper


#@nss_db_init
#def get_cert_obj(cert_sn):
#    """Найти в NSS сертификат по серийному номеру и
#       вернуть его в виде объекта nss.SignedData для дальнейшей обработки"""
#    certs = nss.list_certs(1)
#    for cert in nss.list_certs(nss.PK11CertListAll):
#        logger.debug("--- get_cert_obj(): serial_number %s", cert.serial_number)
#        if cert.serial_number == int(cert_sn):
#            return cert
#    else:
#        raise ValueError("--- No certificate ---")


#### переехала в mod_ldap
#@nss_db_init
#def get_certs_xml(server_name):
#    """Вернуть список сертификатов в виде XML"""
#    logger.debug("=== get_certs_xml")
#    list_certs = nss.list_certs(1)
#    outdict = {"CertDataInfos": {"total": len(list_certs), "CertDataInfo": []}}
#    for cert in list_certs:
#        try:
#            status = "VALID" if bool(cert.verify_now(cert_db, True, 0)) else "INVALID"
#        except error.CertVerifyError:
#            status = "INVALID"
#        certdict =  {
#            "@id": hex(cert.serial_number),
#            "IssuedBy": "admin", # должны быть еще ipara, system. Понять откуда берутся
#            "IssuedOn": int(cert.valid_not_before) // 1000,
#            "IssuerDN": str(cert.issuer),
#            "KeyAlgorithmOID": nss.oid_dotted_decimal((cert.subject_public_key_info.algorithm.id_oid))[4:],
#            "KeyLength": cert.subject_public_key_info.public_key.rsa.modulus.len << 3,
#            "Link": {"@href": "https://%s/ca/rest/certs/%s" % (server_name, hex(cert.serial_number)),"@rel": "self"},
#            "NotValidAfter": int(cert.valid_not_after) // 1000,
#            "NotValidBefore": int(cert.valid_not_before) // 1000,
#            "Status": status,
#            "SubjectDN": str(cert.subject),
#            "Type": "X.509",
#            "Version": cert.version}
#        outdict["CertDataInfos"]["CertDataInfo"].append(certdict)
#    xml = xmltodict.unparse(outdict, short_empty_elements=True)
#    logger.debug("--- xml %s", xml)
#    return xml



@nss_db_init
def get_nickname(uid=""):
    """По uid сертификата найти его никнейм в базе данных NSS.
    uid - уникальная строка, которая однозначно идентифицирует сертификат среди других никтеймов
    """
    cert_nns = nss.get_cert_nicknames(cert_db, nss.SEC_CERT_NICKNAMES_USER)
    for nn in cert_nns:
        if uid in nn:
            return nn
    else: # никнейм корневого центра CN=Certificate Authority,O=TESTDOMAIN.TEST
        return "caSigningCert cert-pki-ca"

@nss_db_init
def get_cert_chain_pem(cert):
    """Получить цепочку сертификатов в формате PEM для cert, где cert это id сертификата или объект класса nss.Certificate"""
    #logger.debug(f"=== nsscerts.get_cert_chanin_pem(%s)", type(cert)) <class 'str'>
    if type(cert) is nss.Certificate:
        cert_obj = cert
    else: # id
        nickname = get_nickname(cert)
        if nickname:
            #logger.debug("--- nickname %s", nickname) # --- nickname caSigningCert cert-pki-ca c54356a1-9222-45b4-8d3f-91b8edaac1c4
            cert_obj_tuple = nss.find_certs_from_nickname(nickname)
            cert_obj = cert_obj_tuple[-1]
        else:
            raise ValueEroor("Пустой никнейм")
    chain_der = cert_obj.get_cert_chain()
    #logger.debug("--- chain_der type: %s", type(chain_der)) # --- chain_der type: <class 'tuple'>
    chain_pem = []
    for der in chain_der:
        #-> pem = mod_ssl.cert_der2pem(der.der_data)
        si_obj = nss.SecItem(der) #->
        pem = si_obj.to_base64(pem_tipe="CERTIFICATE") #->
        chain_pem.append(pem)
    if len(chain_pem) == 0:
        raise ValueError("Пустая цепочка сертификатов")
    return chain_pem


#->def get_cert_chain_pkcs7(cert, form="PEM"):
#->    """Получить цепочку сертификатов PKCS#7 по заданному cert (id сертификата или объект сертификата) в формате form"""
#->    pem_lst = get_cert_chain_pem(cert)
#->    return cert_chain2pkcs7(cert_chain, form)

def get_cert_chain_pkcs7(cert, form="DER"):
    """Получить цепочку сертификатов PKCS#7 по заданному id сертификата или по заданному объекту сертификата"""
    #logger.debug(f"=== nsscerts.get_cert_chanin_pkcs7({type(cert)})") # <class 'str'>
    pem_lst = get_cert_chain_pem(cert)
    cmd = "openssl crl2pkcs7 -nocrl"
    for i, pem in enumerate(pem_lst):
        tmpfile = open(f"/dev/shm/cert{i}", "wb")
        cmd += f" -certfile /dev/shm/cert{i}"
        tmpfile.write(pem)
        tmpfile.close()
    cmd += f" -outform {form} -out /dev/shm/chain.p7b"
    #logger.debug("--- cmd: %s", cmd) # --- cmd: openssl crl2pkcs7 -nocrl -certfile /dev/shm/cert0 -certfile /dev/shm/cert1 -outform DER -out /dev/shm/chain.p7b
    try:
        res = os.system(cmd)
    except Exception as e:
        logger.error("Ошибка %s команды %s -> %s", e, cmd, res)
        return None
    tmpfile = open("/dev/shm/chain.p7b", "rb")
    pkcs7 = tmpfile.read()
    os.system("rm /dev/shm/chain.p7b")
    return pkcs7

def certutil_from_dict(dct):
    """Cборка команды из словаря.
       Элементы словаря имеют вид:
         {"cmd": ""} - запускаемая команда
         {"opt": ""} - ключ/опция задана, но аргумент/значение у нее не предусмотрено;
         {"opt": "value"} - ключ/опция задана и содержит аргумент/значение;
         {"opt": None} - ключ/опция не задана
    """
    ret_lst = []
    for key, arg in dct.items():
        ret_lst.append(key)
        if arg is not None:
            if type(arg) is str and arg.find(" ") > 0:
                arg = "\"" + arg + "\""
            ret_lst.append(str(arg))
    return " ".join(ret_lst)

def new_user_cert_der(csr_pem, serial, issuer_id, valid=12):
    """Выпустить новый сертификат пользователя на основе запроса на выпуск сертификата"""
    with open("/dev/shm/tmpcsr.der", "wb") as csr_der_file:
        try:
            csr_der = mod_ssl.csr_pem2der(csr_pem)
        except Exception as e:
            logger.error("Ошибка %s вызова функции %s", e, "mod_ssl.csr_pem2der")
            return False
        csr_der_file.write(csr_der)
    issuer_nickname = get_nickname(issuer_id)
    logger.info(">--- issuer_nickname: %s", issuer_nickname)
    logger.info(">--- serial:%s", serial)
    logger.info(">--- valid: %s", valid)
    cmd = {
        "certutil": "-C",
        "-c": issuer_nickname,
        "-i": "/dev/shm/tmpcsr.der",
        "-o": "/dev/shm/tmpcert.der",
        "--keyUsage": "digitalSignature,nonRepudiation,keyEncipherment,critical",
        "--extKeyUsage": "clientAuth,critical",
        "-m": serial,
        "-v": valid,
        "-d": db_path,
        "-f": "/etc/pki/pki-tomcat/alias/pwdfile.txt"
    }
    #cmd = 'certutil -C -c "%s" -i /dev/shm/tmpcsr.der -o /dev/shm/tmpcert.der --extKeyUsage clientAuth,critical -m %s -v %s -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/alias/pwdfile.txt' % (issuer_nickname, serial, valid)
    #os.popen(certutil_from_dict(cmd), 'r')
    cmd = certutil_from_dict(cmd)
    logger.info("+++cmd:%s", cmd)
    os.popen(cmd, 'r')
    for i in range(100):
        if os.access("/dev/shm/tmpcert.der", os.F_OK):
            break
    with open("/dev/shm/tmpcert.der", "rb") as cert_file:
        cert_data = cert_file.read()
    logger.info(">--- cert_data: %s", cert_data)
    return cert_data

#def get_cert_fingerprint(cert_obj):
#    """ Получить значения для поля certFingerprint из объекта сертификата """
#    str_lst = cert_obj.signed_data.format().split()
#    out = ""
#    fingerprint = False
#    for word in str_lst:
#        if  word == 'Fingerprint':
#            fingerprint = True
#        else:
#            if fingerprint:
#                if "(" in word and ")" in word:
#                    word = word[1:-2] + ":" # (SHA256): -> SHA256
#                else:
#                    word = "        " + word
#                out += word + "\n"
#    return out

#@nss_db_init
#def get_cert_xml(serial_number):
#    """ipa cert-show"""
#    logger.debug("=== get_certs_xml === %s", serial_number)
#    cert_obj = get_cert_obj(serial_number)
#    data = {}
#    data['certFingerprint'] = get_cert_fingerprint(cert_obj)
#    data['noCertImport'] = "true" # TODO: Что это?
#    data['emailCert'] = "true"    # TODO: Что это?
#    data['serialNumber'] = serial_number
#    data['authorityid'] = "ca"
#    data['reqId'] = serial_number
#    data['pkcs7ChainBase64'] = b64encode(get_cert_chain_pkcs7(cert_obj)).decode()
#    data['certPrettyPrint'] = "Certificate: \n        " + cert_obj.format()
#    data['certChainBase64'] = b64encode(cert_obj.der_data).decode()
#    data['revocationReason'] = 0
#    outdict = {"xml": { "header": data}}
#    logger.debug("--- get_cert_xml(): outdict: %s", outdict)
#    xml = xmltodict.unparse(outdict)
#    logger.debug("--- get_cert_xml(): xml: %s", xml)
#    return xml

@nss_db_init
def get_cert_der(cert_id):
    """Получить сертификат в кодировке DER"""
    nickname = get_nickname(cert_id)
    if nickname:
        cert_obj = nss.find_certs_from_nickname(nickname)
        return cert_obj[-1].der_data
    return None


if __name__ == "__main__":
    # Пример использования:
    #der = get_cert_der("87bffe9d-8fbb-41b4-be44-57a5df85575b")
    #print(der)
    pass
