# Authors:certs_xml = mod_nss.
#get_certs_xml(environ.get('SERVER_NAME','localhost'))
#   Rob Crittenden <rcritten@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
WSGI appliction for astra-ca server.
"""
from __future__ import absolute_import

import logging
import os
import sys
import re
import json
import xmltodict
from urllib.parse import unquote

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(os.path.basename(__file__))

import astra_ca.mod_nss as mod_nss
import astra_ca.mod_ldap as mod_ldap
import astra_ca.mod_ssl as mod_ssl

#import mod_nss
#import mod_ldap
#import mod_ssl

logger.info('*** PROCESS START ***')

def application(environ, start_response):
    logger.info("+++++" + environ.get('REQUEST_URI'," в environ Нет REQUEST_URI"))
    logger.info("ENVIRON: %s", environ )

    # Логин-разлогин
    if environ.get('REQUEST_URI',"") == "/ca/rest/account/login":
        start_response('200 OK', [('Content-Type', 'text/xml'),
                                  ('Set-Cookie', 'ipa_session=MagBearerToken=b%2f04VLsALIGx19LnsBCr%2f8D2YVyvoK5gYRZo7uroa3pwWU0eITJK7VxR9qk%2bNsAkHwd0p2j78Flov%2f7uYHTF6hgrRYOmFUvtuQr5uV9lhUBMCw7SDky0U0AhT0UVdGDSpeK%2br8vAe7sVe8x5SLVWaJ9DKL30UmXgYV5PDq5Hxrn8OF4%2bpVSAXC9wnSSmyf9nIHU%2fxfZ%2bUUZKlD2CbG9%2ftw%3d%3d;path=/ipa;httponly;secure;')
                                 ])
        return [ b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                   <Account id="admin"><Attributes/><Email>root@localhost</Email>
                   <FullName>admin</FullName><Roles><Role>Administrators</Role>
                  <Role>Certificate Manager Agents</Role>
                  <Role>Enterprise CA Administrators</Role>
                  <Role>Enterprise KRA Administrators</Role>
                  <Role>Enterprise OCSP Administrators</Role>
                  <Role>Enterprise RA Administrators</Role>
                  <Role>Enterprise TKS Administrators</Role>
                  <Role>Enterprise TPS Administrators</Role>
                  <Role>Security Domain Administrators</Role></Roles></Account>"""]
    elif environ.get('REQUEST_URI',"") == "/ca/rest/account/logout":
        start_response('200 OK', [('Content-Type', 'text/xml')])
        return [b'']
    # Центры сертификации /ca/rest/authorities
    elif re.match(r'/ca/rest/authorities/.*/chain', environ.get('REQUEST_URI','')): # /ca/rest/authorities/bf2bf802-43c4-4cd8-ac09-5bd0b47b2023/chain
        cert_id = environ['REQUEST_URI'].split("/")[-2]
        #logger.debug("--- cert_id %s", cert_id) # c54356a1-9222-45b4-8d3f-91b8edaac1c4
        pkcs7 = mod_nss.get_cert_chain_pkcs7(cert_id)
        #logger.debug("--- type %s body: %s", type(pkcs7), pkcs7)
        if type(pkcs7) is bytes:
            start_response('200 OK', [('Content-Type', 'application/pkcs7-mime')])
            return [ pkcs7 ]
    elif re.match(r'/ca/rest/authorities/.*/cert', environ.get('REQUEST_URI',"")): # /ca/rest/authorities/bf2bf802-43c4-4cd8-ac09-5bd0b47b2023/cert
        start_response('200 OK', [('Content-Type', 'application/pkix-cert')])
        cert_id = environ['REQUEST_URI'].split("/")[-2]
        #logger.debug("--- cert_id: %s", cert_id)
        der = mod_nss.get_cert_der(cert_id)
        #logger.debug("--- der: %s", der)
        return [der]
    elif environ.get('REQUEST_URI',"") == "/ca/rest/authorities":
        request_method = environ.get('REQUEST_METHOD')
        logger.info("request_method %s", request_method) # POST/GET
        if request_method == "POST":
            wsgi_input = environ.get('wsgi.input','')
            #logger.debug("--- type: %s, wsgi_input: %s", type(wsgi_input), wsgi_input)
            #logger.debug("--- dir: %s", dir(wsgi_input))
            request_body = wsgi_input.read()
            #logger.info("--- request body: %s", request_body) # b'{"parentID": "host-authority", "dn": "cn=test2"}
        elif request_method == "GET": # Вариант пока не проверялся, написан вслепую
            ca_lst = mod_ldap.get_ca_lst()
            if ca_lst:
                start_response('200 OK', [('Content-Type', 'application/json')])
                #logger.info("--- ca_lst: %s", json.dumps(ca_lst).encode())
                return [json.dumps(ca_lst).encode()]

    # Сертификаты
    # ipa cert-find
    elif "/ca/rest/certs/search" in environ.get('REQUEST_URI',''): # /ca/rest/certs/search?size=2147483647
        wsgi_input = environ.get('wsgi.input','')
        request_body = wsgi_input.read()
        logger.debug("--- request body: %s", request_body) 
        req_ordered_dict = xmltodict.parse(request_body.decode())
        if req_ordered_dict['CertSearchRequest']['subjectInUse'] == "true":
            cert_lst = mod_ldap.get_certs(environ.get('SERVER_NAME','localhost'), subject_name=req_ordered_dict['CertSearchRequest']['commonName'])
        else:
            cert_lst = mod_ldap.get_certs(environ.get('SERVER_NAME','localhost'))
        certs_xml = xmltodict.unparse(cert_lst, short_empty_elements=True)
        #logger.info("--- responce body: %s", certs_xml)
        if len(cert_lst) > 0:
            start_response('200 OK', [('Content-Type', 'application/xml;charset=UTF-8')])
            return [certs_xml.encode()]
    # ipa cert-show <serial_number>
    elif "/ca/displayBySerial" in environ.get('REQUEST_URI',''): 
        start_response('200 OK', [('Content-Type', 'application/xml;charset=UTF-8')])
        wsgi_input = environ.get('wsgi.input','')
        request_body = wsgi_input.read()
        logger.info("--- displayBySerial request body: %s", request_body) # b'serialNumber=1&xml=true'
        for item in request_body.decode().split("&"):
           if 'serialNumber' in item:
              serial_number = item.split("=")[1]
              break
        cert_dict = mod_ldap.get_cert(serial_number)
        xml = xmltodict.unparse(cert_dict)
        logger.debug("--- get_cert(): xml: %s", xml)
        return [xml.encode()]

    elif '/ca/agent/ca/doRevoke' in environ.get('REQUEST_URI',''):
        start_response('200 OK', [('Content-Type', 'application/xml;charset=UTF-8')])
        wsgi_input = environ.get('wsgi.input','')
        request_body = wsgi_input.read()
        logger.debug("--- request body: %s", request_body) # b'op=revoke&revocationReason=6&revokeAll=%28certRecordId%3D6%29&totalRecordCount=1&xml=true'
        request = unquote(request_body.decode()) # op=revoke&revocationReason=6&revokeAll=(certRecordId=6)&totalRecordCount=1&xml=true
        #logger.debug("--- request: %s", request)
        for item in request.split("&"):
            if "revocationReason" in item:
                revocation_reason = item.split("=")[-1]
            if "revokeAll" in item:
                serial_number = item.split("certRecordId=")[-1][:-1]
                #logger.debug("--- serial_number: %s", serial_number)
        result, descr = mod_ldap.revoke_cert(serial_number, revocation_reason)
        if result:
            ret = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><xml><header><dirEnabled>no</dirEnabled><error/><revoked>yes</revoked><totalRecordCount>1</totalRecordCount></header><fixed/><records><record><error/><serialNumber>' + serial_number + '</serialNumber></record></records></xml>'
        else:
            ret = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><xml><header/><fixed><errorDetails>'+ descr + '</errorDetails><authorityName>Certificate Manager</authorityName><requestStatus>6</requestStatus></fixed><records/></xml>'
        return [ret.encode()]
    elif '/ca/agent/ca/doUnrevoke' in environ.get('REQUEST_URI',''):
        start_response('200 OK', [('Content-Type', 'application/xml;charset=UTF-8')])
        wsgi_input = environ.get('wsgi.input','')
        request_body = wsgi_input.read()
        logger.debug("--- request body: %s", request_body) # b'serialNumber=6&xml=true'
        for item in request_body.decode().split("&"):
            if "serialNumber" in item:
                serial_number = item.split("=")[-1]
                break
        result, descr = mod_ldap.remove_hold_cert(serial_number)
        if result:
            ret = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><xml><header><dirEnabled>no</dirEnabled><serialNumber>' + serial_number +'</serialNumber><unrevoked>yes</unrevoked></header><fixed/><records/></xml>'
        else:
            ret = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><xml><header><dirEnabled>no</dirEnabled><error>' + descr + '</error><serialNumber>' + serial_number + '</serialNumber><unrevoked>no</unrevoked></header><fixed/><records/></xml>'
        return [ret.encode()]
    elif '/ca/rest/certrequests' in environ.get('REQUEST_URI',''): # /ca/rest/certrequests?issuer-id=bf2bf802-43c4-4cd8-ac09-5bd0b47b2023
        if environ.get('REQUEST_METHOD') == "POST":
            wsgi_input = environ.get('wsgi.input', '')
            req_body = wsgi_input.read()
            logger.info(">--- request body: %s", req_body) # --- request body: b'<?xml version="1.0" encodin
            logger.info(">--- environ:%s", environ)
            issuer_id = environ.get('QUERY_STRING','').split('=')[1] if 'issuer-id' in environ.get('QUERY_STRING','') else ""
            #logger.debug("--- issuer_id: %s", issuer_id) # c54356a1-9222-45b4-8d3f-91b8edaac1c4
            req_ordered_dict = xmltodict.parse(req_body)
            logger.info("--- req_ordered_dict: %s", req_ordered_dict) # OrderedDict([('CertEnrollmentRequest', OrderedDict([('ProfileID', 'IECUserRoles'), ('Input', OrderedDict([('@id', 'i1')...
            profile_id = req_ordered_dict['CertEnrollmentRequest']['ProfileID']
            cert_req_pem = req_ordered_dict['CertEnrollmentRequest']['Input']['Attribute'][1]['Value']
            #---email---
            #logger.info(">>> type:%s, cert_req_pem:%s", type(cert_req_pem), cert_req_pem)
            #cert_req_obj = mod_ssl.get_csr_obj(cert_req_pem)
            #subj = cert_req_obj.subject
            #logger.info(">>> subj:%s", subj.rfc4514_string())
            #subj_lst = get_subject_lst(subj)
            #---email---
            cert_request_type = req_ordered_dict['CertEnrollmentRequest']['Input']['Attribute'][0]['Value']
            #logger.debug("%s", cert_req_pem) # -----BEGIN CERTIFICATE REQUEST-----....
            new_serial = mod_ldap.get_next_serial()
            logger.info("---new_serial: %s", new_serial) # --- 26
            cert_der = mod_nss.new_user_cert_der(cert_req_pem, new_serial, issuer_id)
            logger.debug("---cert_der: %s", cert_der)
            cert_req_id = mod_ldap.get_next_req_id()
            logger.debug("---cert_req_id: %s", cert_req_id) # --- 55 ...
            if mod_ldap.insert_cert(new_serial, cert_der, cert_req_id, profile_id):
                mod_ldap.insert_cert_request(cert_req_id, cert_req_pem.encode(), profile_id, environ.get('REMOTE_ADDR',''), cert_request_type, issuer_id) #### TODO
                req_url = environ.get('REQUEST_SCHEME') + "://" + environ.get('HTTP_HOST') + "/ca/rest/certrequests/" + str(cert_req_id)
                cert_url = environ.get('REQUEST_SCHEME') + "://" + environ.get('HTTP_HOST') + "/ca/rest/certs/" + str(new_serial)
                cert_req_type = req_ordered_dict['CertEnrollmentRequest']['Input']['Attribute'][0]['Value']
                response = {"total": 1, "entries": [{"requestType": "enrolment", "requestStatus": "complete","requestURL": req_url, 
                   "realm": None, "certId": hex(new_serial), "certURL": cert_url, "certRequestType": cert_req_type, 
                   "operationResult": "success", "errorMessage": None}], "Link": []}
                #logger.debug("--- response %s", response) # --- response {'total': 1, 'entries':....
                start_response('200 OK', [('Content-Type', 'application/json')])
                return [json.dumps(response).encode()]
    elif environ.get('REQUEST_URI',"") == "/ca/admin/ca/getStatus":
        # Для ipa-pki-wait-running, systemd конфига, который проверяет, что демон pki-tomcatd запущен и отвечает
        start_response('200 OK', [('Content-Type', 'application/json')])
        body = {'Response': {'State': '1', 'Type': 'CA', 'Status': 'running', 'Version': '11.2.1', 'ProductVersion': 'Astra Certificate System'}}
        return [json.dumps(body).encode()]
    else:
        # По умолчанию
        start_response('200 OK', [('Content-Type', 'text/html')])
        return [b'<html><p>REQUEST_METHOD: ', environ['REQUEST_METHOD'].encode(),
            b"<p>QUERY_STRING: ", environ['QUERY_STRING'].encode(), 
            b'<p>REQUEST_URI: ', environ['REQUEST_URI'].encode(),
            b'</html>']
