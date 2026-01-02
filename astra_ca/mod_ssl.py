#!/usr/bin/python3

"""Библиотека функций обработки сертификатов c использованием библиотеки SSL"""

import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64
import logging
from cryptography.hazmat.primitives.serialization import pkcs7

logger = logging.getLogger(os.path.basename(__file__))


# Больше не используется, раньше вызывалась из nss.get_cert_chain_pem
#->def cert_der2pem(der):
#->    """Конвертировать сертификат из формата DER в PEM"""
#->    cert_x509 = x509.load_der_x509_certificate(der, backend=default_backend())
#->    return cert_x509.public_bytes(serialization.Encoding.PEM)


def cert_chain2pkcs7(cert_obj_chain, form="PEM"):
    """Закодировать цепочку сертификатов в формат PKCS#7 (PEM и DER)"""
    if form == "PEM":
        return pkcs7.serialize_certificates(cert_obj_chain, serialization.Encoding.PEM) # b'-----BEGIN PKCS7-----\nMIIGlAYJK ...
    elif form == "DER":
        return pkcs7.serialize_certificates(cert_obj_chain, serialization.Encoding.DER)
    else:
        raise ValueError("Аргумент form должен иметь значение 'PEM' или 'DER'")

def get_csr_obj(pem):
    """ Получить объект запроса на сертификат"""
    if type(pem) is str:
        pem = pem.encode()
    return x509.load_pem_x509_csr(pem, backend=default_backend())

def csr_pem2der(pem):
    """Конвертировать запрос на выпуск сертификата из формата PEM в DER"""
    #if type(pem) is str:
    #    pem = pem.encode()
    #csr_obj = x509.load_pem_x509_csr(pem, backend=default_backend())
    csr_obj = get_csr_obj(pem)
    return csr_obj.public_bytes(serialization.Encoding.DER)

def get_cert_key_len(der):
    """Получить длинну публичного ключа сертификата"""
    cert_x509 = x509.load_der_x509_certificate(der, backend=default_backend())
    pk = cert_x509.public_key()
    return pk.key_size

def get_cert_obj(data, form="DER"):
    """Возвращает объект класса cryptography.x509.Certificate"""
    if type(data) is str:
        data = data.encode()
    if form == "DER":
        cert_obj = x509.load_der_x509_certificate(data, backend=default_backend())
    elif form == "PEM":
        cert_obj = x509.load_pem_x509_certificate(data, backend=default_backend())
    else:
        raise ValueError("Аргумент form должен иметь значение 'PEM' или 'DER'")
    return cert_obj

def get_public_bytes(obj, form="PEM"):
    """Возвращает сеариализированный объект"""
    if form == "PEM":
        return obj.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    elif form == "DER":
        return obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    elif form == "BASE64":
        return base64.b64encode(obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1))
    else:
        raise ValueError("Аргумент form должен быть 'PEM','BASE64' или 'DER")

def get_cert_fingerprint(cert): 
    return cert.fingerprint(hashes.SHA256())

def get_cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)

def pretty_print(cert):
    """Возвращает сертификат в виде человекочитаемого текста"""
    tmpfile = open("/dev/shm/tmpcert.pem", "wb")
    tmpfile.write(cert)
    tmpfile.close()
    cmd = "openssl x509 -in /dev/shm/tmpcert.pem -noout -text"
    try:
        out = os.popen(cmd)
    except Exception as e:
        logger.error("Ошибка %s команды %s -> %s", e, cmd, res)
        return None
    return out.read()

def get_subject_lst(subject_obj):
    """Получить список компонентов поля subject в виде словаря
      {'countryName': 'RU', 'commonName': 'ipauser02', 'emailAddress': 'ipauser02@testdomain.test'}"""
    ret_lst = {}
    for i in subject_obj:
        ret_lst[i.oid._name] = i.value
    return ret_lst

def get_email_from_subject(cert_obj):
    for key, value in get_subject_lst(cert_obj.subject).items():
        if key == 'emailAddress':
           return value
    return None

def get_email_from_ext(cert_obj):
    """Получить адрес ЭП из расширения SubjectAlternativeName сертификата"""
    for ext in cert_obj.extensions:
        if type(ext.value) is x509.extensions.SubjectAlternativeName:
            for value in ext.value.get_values_for_type(x509.GeneralName):
                if '@' in value:
                    return value
    return None
