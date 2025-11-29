#!/usr/bin/python3

import astra_ca.mod_ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def test_get_email_from_subject():
    csr_pem=b"""-----BEGIN CERTIFICATE REQUEST-----
MIICkDCCAXgCAQAwSzELMAkGA1UEBhMCUlUxEjAQBgNVBAMMCWlwYXVzZXIwMjEo
MCYGCSqGSIb3DQEJARYZaXBhdXNlcjAyQHRlc3Rkb21haW4udGVzdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOok9E99GQSMz1ruOe7CbweB/d/lyOz/
hqn2CHcXM+H3yMps39uzVFkRQezJGeJ2zANkC9vlyh3aB1FznOdYLLpYkOJ8Q/KN
ZMfLRPjzVQ/OKkhD5M5Oq827/2ApJS/BL+8wg7RbzSHwvcmRTT5zKmmHT/kK3Zta
xesvduLNREilqTQ0nFgPIZSGngIGinzOV6JxirECEljsAWY9OS+jOt57I+yr1/GT
de3T5flz3UvAJiOsoXq4xcNAyQVBZKJmFdZCE9G8rwL7pDHsSK6jcKY/e74Pw6P3
BekHieOezyDHhXzj09Kip74ohXF+RSuU7Yo1Km+BR3GdIsZhEFr8UqMCAwEAAaAA
MA0GCSqGSIb3DQEBCwUAA4IBAQAxHfFxnDjw8n0ZtPwBD+FCurNGQKIizlI67Y8n
dvcK50LGurV67ZmQa5FNeTWYil9DcohDSmOnxiY9wlyxRnfVj6yeVwSiZpgTHtZo
5et3zr/oRNCprHeSc7JRiFHbdwvVjec0YNDXsZjWEy0IlIapsqDCcm1YMUdjG4IX
40xL0RwVZKMvRy7zFf94LX72aEWdAPKX0uYdrb6HecENlFWl8Z8/6qSr3gpGjvNx
YwAt+Td85bC77N4fka1kZhO+YLwXlaOIJMOz8Yn4sGGlSxFBLbDmU3D1K98Vsptu
0odwY8YQMwSZZGMEISd9tQMU9WghvEx3gtpPnwS9jgd5hmFw
-----END CERTIFICATE REQUEST-----"""

    csr_obj =  x509.load_pem_x509_csr(csr_pem, backend=default_backend())
    assert astra_ca.mod_ssl.get_email_from_subject(csr_obj) == "ipauser02@testdomain.test"
