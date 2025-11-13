#!/usr/bin/python3

"""Библиотека функций обработки сертификатов c использованием библиотеки SSL"""

import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import base64
import logging

logger = logging.getLogger(os.path.basename(__file__))

def cert_der2pem(der):
    """Конвертировать сертификат из формата DER в PEM"""
    cert_x509 = x509.load_der_x509_certificate(der, backend=default_backend())
    return cert_x509.public_bytes(serialization.Encoding.PEM)

def csr_pem2der(pem):
    """Конвертировать запрос на выпуск сертификата из формата PEM в DER"""
    csr_x509 = x509.load_pem_x509_csr(pem.encode(), backend=default_backend())
    return csr_x509.public_bytes(serialization.Encoding.DER)

def get_cert_key_len(der):
    """Получить длинну публичного ключа сертификата"""
    cert_x509 = x509.load_der_x509_certificate(der, backend=default_backend())
    pk = cert_x509.public_key()
    return pk.key_size

def get_cert_obj(der):
    """Возвращает объект класса cryptography.x509.Certificate"""
    cert_x509 = x509.load_der_x509_certificate(der, backend=default_backend())
    return cert_x509

def get_csr_obj(pem):
    """ Получить объект запроса на сертификат"""
    if type(pem) is str:
        pem = pem.encode()
    csr_x509 = x509.load_pem_x509_csr(pem,  backend=default_backend())
    return csr_x509

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
