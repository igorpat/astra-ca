#!/usr/bin/python3

import ldap


db = ldap.initialize("ldap://localhost:389")
db.simple_bind_s("cn=Directory Manager", "12345678")
#print(db.whoami_s())
"""
print(">1<")
dn = "cn=ipaca,cn=ldbm database,cn=plugins,cn=config"
add_lst = [("objectclass", b"top"), 
           ("objectclass", b"extensibleObject"), 
           ("objectclass", b"nsMappingTree"),
           ("cn", b"ipaca"),
           ("nsslapd-suffix", b"o=ipaca")
          ]
print("--")
db.add_s(dn, add_lst)
"""

# config
#dn: cn=config
#changetype: modify
#add: nsslapd-backendconfig
print(">2<")
dn="cn=config"
mod_lst = [(ldap.MOD_ADD, "nsslapd-backendconfig", b"cn=conifg,o=ipaca,cn=ldbm database,cn=plugins,cn=config")]
db.modify_s(dn, mod_lst)
print(">3<")

#dn='cn="o=ipaca",cn=mapping tree,cn=config'
dn='cn="o=ipaca",cn=mapping tree,cn=config'
add_lst = [("objectclass", b"top"), 
           ("objectclass", b"extensibleObject"), 
           ("objectclass", b"nsMappingTree"),
           ("cn", b"o=ipaca"),
           ("nsslapd-state", b"Backend"),
           ("nsslapd-backend", b"ipaca")
          ]
print("--")
db.add_s(dn, add_lst)

print("###")
db.unbind_s()
print(db)
