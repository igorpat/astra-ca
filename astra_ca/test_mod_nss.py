#!/usr/bin/python3

import astra_ca.mod_nss

def test_cmd_from_dict():
    """pytest-3"""
    issuer_nickname = "caSigningCert cert-pki-ca"
    valid = 12
    #result = "certutil -C -c issuer_nickname -i /dev/shm/tmpcsr.der -o /dev/shm/tmpcert.der --extKeyUsage clientAuth,critical -m 1234 -v valid -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/alias/pwdfile.txt"
    result = 'certutil -C -c "caSigningCert cert-pki-ca" -i /dev/shm/tmpcsr.der -o /dev/shm/tmpcert.der --extKeyUsage clientAuth,critical -m 32 -v 12 -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/alias/pwdfile.txt'
    cmd_dct = {
        "certutil": "-C",
        "-c": issuer_nickname,
        "-i": "/dev/shm/tmpcsr.der",
        "-o": "/dev/shm/tmpcert.der",
        "--extKeyUsage": "clientAuth,critical",
        "-m": 32,
        "-v": valid,
        "-d": "/etc/pki/pki-tomcat/alias",
        "-f": "/etc/pki/pki-tomcat/alias/pwdfile.txt"
    }
    assert result == astra_ca.mod_nss.certutil_from_dict(cmd_dct)


