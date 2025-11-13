#!/usr/bin/python3

"""Библиотека функций для работы с LDAP"""

import os
import time
import logging
from base64 import b64encode
import ldap
import astra_ca.mod_ssl as mod_ssl
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(os.path.basename(__file__))

db_url = 'ldap://localhost:389'
db_user = 'cn=Directory Manager'
db_pass = '12345678'

def ldap_db_init(func):
    """Инициализация подключения к базе данных LDAP"""
    def wrapper(*args, **kwargs):
        if not "ldap_db" in globals():
            global ldap_db
            ldap_db = ldap.initialize(db_url)
            ldap_db.bind_s(db_user, db_pass)
        return func(*args, **kwargs)
    return wrapper

# Тестовая функция
@ldap_db_init 
def get_whoami():
    return ldap_db.whoami_s()

@ldap_db_init
def get_parent_ca():
    """Найти родительский для других центр авторизации"""
    basedn = "ou=authorities,ou=ca,o=ipaca"
    cas = ldap_db.search_s(basedn, ldap.SCOPE_ONELEVEL)
    for ca in cas: 
        pd = ca[1].get('authorityParentDN')
        if pd is None:
            return ca[1]['authorityDN'][0], ca[1]['authorityID'][0] # (b'CN=Certificate Authority,O=TESTDOMAIN.TEST', b'bf2bf802-43c4-4cd8-ac09-5bd0b47b2023')

@ldap_db_init
def get_ca_lst():
    """ Вывести список центров авторизации"""
    ca_lst = ldap_db.search_s('ou=authorities,ou=ca,o=ipaca', ldap.SCOPE_ONELEVEL)
    result = []
    for ca in ca_lst:
        authority = {}
        if ca[1].get('authorityID'): authority['id'] = ca[1].get('authorityID')[-1].decode()
        if ca[1].get('authorityParentDN'): authority['issuerDN'] = ca[1].get('authorityParentDN')[-1].decode()
        if ca[1].get('authoritySerial'): authority['serial'] = ca[1].get('authoritySerial')[-1].decode()
        if ca[1].get('authorityDN'): authority['dn'] = ca[1].get('authorityDN')[-1].decode()
        if ca[1].get('authorityEnabled')[-1].lower(): authority['enabled'] = ca[1].get('authorityEnabled')[-1].decode().lower()
        if ca[1].get('description'): authority['description'] = ca[1].get('description')[-1].decode()
        authority['ready'] = 'true' # TODO: не понятно откуда брать ready. В ЛДАП не нашел, может в nss
        result.append(authority)
    return result

def _get_seconds(time_str, form='%Y%m%d%H%M%SZ'): # '20250416110305Z' -> 1744790585
    """Преобзразование форматной строки времени в кол-во секунд с начала эпохи"""
    t = time.strptime(str(time_str), form) # -> time.struct_time(tm_year=2025, tm_mon=4, tm_mday=16, tm_hour=11, tm_min=3, tm_sec=5, tm_wday=2, tm_yday=106, tm_isdst=-1)
    return int(time.mktime(t))

def _get_cur_ztime(form='%Y%m%d%H%M%SZ'):
    """Получени форматной строки текущего всемирного координированного времени (UTC)"""
    return time.strftime('%Y%m%d%H%M%SZ', time.gmtime())

def _convert_time(time_str, inform="%Y-%m-%d %H:%M:%S", outform="%Y%m%d%H%M%SZ"):
    """Изменение формата представления времени"""
    t = time.strptime(str(time_str), inform)
    return time.strftime(outform, t)


@ldap_db_init
def get_certs(server_name, subject_name=None): # ipa cert-find
    """Вернуть список сертификатов"""
    filt='objectClass=certificateRecord'
    if subject_name:
        filt="(&(objectClass=certificateRecord)(subjectName=CN=" + subject_name + "*))"
    logger.debug("=== get_certs filt: %s", filt)
    attr_lst = ['cn', 'issuedBy', 'dateOfCreate', 'algorithmId', 'issuerName',  'notAfter','notBefore', 'certStatus', 'subjectName','userCertificate','version' ]
    list_certs = ldap_db.search_s('ou=certificateRepository,ou=ca,o=ipaca', ldap.SCOPE_ONELEVEL, filt, attrlist=attr_lst)
    outdict = {"CertDataInfos": {"total": len(list_certs), "CertDataInfo": []}}
    for cert in list_certs:
        certdict =  {
            "@id": hex(int(cert[1]['cn'][-1].decode())),
            "IssuedBy": cert[1]['issuedBy'][-1].decode(),
            "IssuedOn": _get_seconds(cert[1]['dateOfCreate'][-1].decode()),
            "IssuerDN": cert[1]['issuerName'][-1].decode(),
            "KeyAlgorithmOID": cert[1]['algorithmId'][-1].decode(),
            "KeyLength": mod_ssl.get_cert_key_len(cert[1]['userCertificate;binary'][-1]),
            "Link": {"@href": "https://%s/ca/rest/certs/%s" % (server_name, hex(int(cert[1]['cn'][-1].decode()))), "@rel": "self"},
            "NotValidAfter": _get_seconds(cert[1]['notAfter'][-1].decode()),
            "NotValidBefore": _get_seconds(cert[1]['notBefore'][-1].decode()),
            "Status": cert[1]['certStatus'][-1].decode(),
            "SubjectDN": cert[1]['subjectName'][-1].decode(),
            "Type": "X.509",
            "Version": cert[1]['version'][-1].decode()}
        outdict["CertDataInfos"]["CertDataInfo"].append(certdict)
    #logger.debug("--- get_certs: %s", outdict)
    return outdict

@ldap_db_init
def get_next_serial():
    """Определить очередной серийный номер сертификата"""
    filt='objectClass=certificateRecord'
    attr_lst = ['cn', 'serialno']
    serial_lst = ldap_db.search_s('ou=certificateRepository,ou=ca,o=ipaca', ldap.SCOPE_ONELEVEL, filt, attrlist=attr_lst)
    return len(serial_lst) + 1

def get_next_req_id():
    """Определить очередной номер запроса на выпуск сертификата"""
    filt='objectClass=request'
    attr_lst = ['cn', 'requestId']
    req_lst = ldap_db.search_s('ou=ca,ou=requests,o=ipaca', ldap.SCOPE_ONELEVEL, filt, attrlist=attr_lst)
    return len(req_lst) + 1


def _get_cert_entry(cert_sn):
    """Найти в LDAP сертификат по серийному номеру и вернуть его в виде словаря"""
    attr_lst = ['cn', 'userCertificate', 'revInfo', 'metaInfo']
    filt='(&(cn=' + cert_sn + ')(objectClass=certificateRecord))'
    logger.info("---filt: %s", filt)
    list_certs = ldap_db.search_s('ou=certificateRepository,ou=ca,o=ipaca', ldap.SCOPE_ONELEVEL, filt, attrlist=attr_lst)
    if list_certs:
        #logger.debug("--- cert %s", list_certs[0][1])
        return list_certs[0][1]
    else:
        raise ValueError("Сертификат с серийным номером %s не найден!" % cert_sn)

@ldap_db_init
def revoke_cert(serial_number, revocation_reason):
    """Отозвать сертификат"""
    cur_time = time.strftime('%Y%m%d%H%M%SZ')
    dn = 'cn=' + serial_number + ',ou=certificateRepository,ou=ca,o=ipaca'
    rev_info = "%s;CRLReasonExtension=%s" % (cur_time, revocation_reason)
    mod_lst = [(ldap.MOD_REPLACE, 'revokedBy', b'ipara'),
                (ldap.MOD_REPLACE, 'revokedOn', cur_time.encode()),
                (ldap.MOD_REPLACE, 'revInfo', rev_info.encode()),
                (ldap.MOD_REPLACE, 'certStatus', b'REVOCED')]
    try:
        ldap_db.modify_s(dn, mod_lst)
        return True, ""
    except Exception as e:
        return False, e.args[0]['desc']

@ldap_db_init
def remove_hold_cert(serial_number):
    """Отменить отзыв сертификата 
       (должно применяться для сертификатов с причиной отзыва "приостановка действия" (6) CERTIFICATE_HOLD)
    """
    cert_dict = _get_cert_entry(serial_number)
    if "CRLReasonExtension=6" not in cert_dict['revInfo'][-1].decode():
        return False, "Attempt to revoke non-existent certificate(s)."
    dn = 'cn=' + serial_number + ',ou=certificateRepository,ou=ca,o=ipaca'
    mod_lst = [(ldap.MOD_REPLACE, 'revokedBy', None),
                (ldap.MOD_REPLACE, 'revokedOn', None),
                (ldap.MOD_REPLACE, 'revInfo', None),
                (ldap.MOD_REPLACE, 'certStatus', b'VALID')]
    try:
        ldap_db.modify_s(dn, mod_lst)
        return True, ""
    except Exception as e:
        return False, e.args[0]['desc']

def _get_dn_str(name_obj):
    """Получить строку DN из объекта cryptography.x509.Name (в которой хранятся issuer и subject"""
    rdn_lst = []
    for i in reversed(name_obj.rdns):
        if 'CN=' in i.rfc4514_string() or 'O=' in i.rfc4514_string():
            rdn_lst.append(i.rfc4514_string())
    if rdn_lst:
        return ",".join(rdn_lst)
    else:
        raise ValueError("Нет удалось получить строку DN из %s", name_obj)

def _get_ext_oids(cert_extensions):
    oid_lst = []
    for ext in cert_extensions:
        oid_lst.append(ext.oid.dotted_string.encode())
    return oid_lst

@ldap_db_init
def insert_cert_request(next_number, req_pem, profile_id, remote_ip, request_type, issuer_id):
    csr_obj = mod_ssl.get_csr_obj(req_pem)
    pk_obj = csr_obj.public_key()
    pub_key = mod_ssl.get_public_bytes(pk_obj, form="BASE64")
    date = _get_cur_ztime()

    dn = "cn=%d,ou=ca,ou=requests,o=ipaca" % next_number
    add_lst = [("cn", str(next_number).encode()),
                ("objectClass", b"top"),
                ("objectClass", b"request"),
                ("objectClass", b"extensibleObject"),
                ("dateOfCreate", date.encode()),
                ("dateOfModify", date.encode()), 
                ("extdata-cert-005frequest", req_pem),
                ("extdata-cert--005frequest--005ftype", request_type.encode()),
                ("extdata-profileid", profile_id.encode()),
                ("extdata-profileremoteaddr", remote_ip.encode()),
                ("extdata-req--005fauthority--005fid", issuer_id.encode()),
                ("extdata-req--005fkey", pub_key),
                ("requestId", str(next_number).encode()),
                ("requestState", b'complete'),
              ]
    return ldap_db.add_s(dn, add_lst)

@ldap_db_init
def insert_cert(next_number, cert_der, req_id, profile_id):
    """ipa cert-request"""
    dn = 'cn=%d,ou=certificateRepository,ou=ca,o=ipaca' % next_number
    cert_obj = mod_ssl.get_cert_obj(cert_der)
    serial_number = cert_obj.serial_number
    algorithm_id = cert_obj.signature_algorithm_oid.dotted_string
    date_of_create = _convert_time(cert_obj.not_valid_before)
    date_of_valid = _convert_time(cert_obj.not_valid_after)
    duration = _get_seconds(date_of_valid) - _get_seconds(date_of_create)
    public_key_data = cert_obj.public_bytes(serialization.Encoding.DER)
    issuer_name = _get_dn_str(cert_obj.issuer)
    subject_name = _get_dn_str(cert_obj.subject)
    version = cert_obj.version.value
    profile_id = "profileId:%s" % profile_id
    request_id = "requestId:%d" % req_id
    ext_lst = _get_ext_oids(cert_obj.extensions)

    add_lst = [("cn", str(serial_number).encode()),
                ("objectClass", b"top"),
                ("objectClass", b"certificateRecord"),
                ("algorithmId", b"1.2.840.113549.1.1.1"), # RSA encryption
                ("autoRenew", b"ENABLED"), 
                ("certStatus", b"VALID"),
                ("dateOfCreate", date_of_create.encode()),
                ("dateOfModify", date_of_create.encode()),
                ("duration", str(duration * 1000).encode()),
                ("extension", ext_lst),
                ("issuedBy", b"ipara"), 
                ("issuerName", issuer_name.encode()),
                ("metaInfo", [profile_id.encode(), request_id.encode()]),
                ("notAfter", date_of_valid.encode()),
                ("notBefore", date_of_create.encode()),
                ("publicKeyData", [public_key_data]),
                ("serialno", str(serial_number).encode()),
                ("signingAlgorithmId", algorithm_id.encode()),
                ("subjectName", subject_name.encode()),
                ("userCertificate;binary", [cert_der]),
                ("version", str(version).encode())
               ]
                  
    logger.info("oooooo %s %s", dn, add_lst)
    return ldap_db.add_s(dn, add_lst)


@ldap_db_init
def get_cert(serial_number):
    """ipa cert-show"""
    logger.debug("=== get_certs === %s", serial_number)
    cert_dict = _get_cert_entry(serial_number)
    logger.debug("--- cert_dict: %s", cert_dict) 
    cert_obj = mod_ssl.get_cert_obj(cert_dict['userCertificate;binary'][-1])
    #cert_obj = mod_ssl.get_cert_obj(cert_dict['userCertificate'][-1])
    # dir(cert_obj):
    # 'extensions', 'fingerprint', 'issuer', 'not_valid_after', 'not_valid_before', 'public_bytes', 'public_key', 'serial_number', 
    # 'signature', 'signature_algorithm_oid', 'signature_hash_algorithm', 'subject', 'tbs_certificate_bytes', 'version']
    #logger.debug("--- cert_obj: %s", cert_obj.extensions)
    data = {}
    data['certFingerprint'] = str(mod_ssl.get_cert_fingerprint(cert_obj))
    data['noCertImport'] = "true" # TODO: Что это?
    data['emailCert'] = "true"    # TODO: Что это?
    data['serialNumber'] = hex(cert_obj.serial_number)
    data['authorityId'] = "ca" # TODO: почему-то нигде не используется
    for item in cert_dict['metaInfo']:
        if b'requestId' in item:
            data['reqId'] = item.decode().split(':')[1]
            break
    # Без следующих закоментированных вещей вроде все работает
    #data['pkcs7ChainBase64'] = b64encode(mod_nss.get_cert_chain_pkcs7(cert_dict['userCertificate'][-1])).decode()
    #cert_pem = mod_ssl.get_cert_pem(cert_obj)
    #data['certPrettyPrint'] = mod_ssl.pretty_print(cert_pem)
    data['certChainBase64'] = b64encode(cert_dict['userCertificate;binary'][-1]).decode()
    #data['certChainBase64'] = b64encode(cert_dict['userCertificate'][-1]).decode()
    if cert_dict.get('revInfo'): # [b'20250411173935Z;CRLReasonExtension=0']
        data['revocationReason'] = cert_dict['revInfo'][-1].decode().split(';')[1].split('=')[1]
    #revocation reason may be one of:
    # 0 = UNSPECIFIED
    # 1 = KEY_COMPROMISE
    # 2 = CA_COMPROMISE
    # 3 = AFFILIATION_CHANGED
    # 4 = SUPERSEDED
    # 5 = CESSATION_OF_OPERATION
    # 6 = CERTIFICATE_HOLD
    # 8 = REMOVE_FROM_CRL
    # 9 = PRIVILEGE_WITHDRAWN
    # 10 = AA_COMPROMISE
    return {"xml": { "header": data}}


if __name__ == "__main__":
    print(get_whoami())
    #print(get_parent_ca())
    #r = get_ca_lst()
    pass
