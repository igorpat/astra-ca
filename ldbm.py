#!/usr/bin/python3

import sys
import ldap
import ldap.modlist as modlist
import time

def setup_ldbm(host='localhost', 
               port=389, 
               binddn="cn=Directory Manager", 
               bindpw="12345678", 
               ldapentry=None, 
               ldapdn=None
              ):
    ldap_db = ldap.initialize('ldap://' + host + ':' + str(port))
    try:
        ldap_db.bind_s(binddn, bindpw)
    except (ldap.SERVER_DOWN, e):
        print(" LDAP server is down")
        return False
    else:
        print(" Bind Successful")

    attrs = modlist.addModlist(ldapentry)
    print(" attrs = ", attrs)
    try:
        ldap_db.add_s(ldapdn, attrs)
    except:
        raise
    else:
        print(" %s succesfully added" % (ldapdn))
        return True
    finally:
        ldap_db.unbind()
        del ldap_db

if len(sys.argv) == 1:
    print("for test")
    RootDC = "o=ipaca"
    BindDN = "cn=Directory Manager"
    BindPW = "12345678"
else:
    RootDC = sys.argv[1] #"o=%s" % DBName
    print(" RootDC:", RootDC)
    BindDN = sys.argv[2]
    BindPW = sys.argv[3]

DBName = RootDC.split("=")[1] # ipaca
print(" DBName:", DBName)

RootDCMapping = "%s,cn=mapping tree,cn=config" % RootDC

entry1 = {
        'objectClass' : [b'extensibleObject', b'nsBackendInstance'],
        'nsslapd-suffix' : [RootDC.encode()]
        }
dn1 = 'cn=%s,cn=ldbm database,cn=plugins,cn=config' % DBName

entry2 = {
        'objectClass':[b'top', b'extensibleObject', b'nsMappingTree'],
        'nsslapd-state' : b'backend',
        'nsslapd-backend' : DBName.encode(),
        'cn' : RootDC.encode()
        }
dn2 = RootDCMapping

r1 = setup_ldbm(ldapentry=entry1, ldapdn=dn1)
if not r1:
    sys.exit(1)
time.sleep(1)
r2 = setup_ldbm(ldapentry=entry2, ldapdn=dn2)
if not r2:
    sys.exit(2)
#entry3 = {
#        'objectClass': [b'top', b'dcObject', b'organization'],
#        'dc' : [DBName.encode()],
#        'o' : [DBName.encode()]
#        }
entry3 = {'objectClass': [b'top', b'organization'],
          'o' : [DBName.encode()]
         }

dn3 = RootDC
r3 = setup_ldbm(ldapentry=entry3, ldapdn=dn3)
if not r3:
    sys.exit(3)
