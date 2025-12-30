#!/bin/bash

exec &> /var/log/pkispawn.log

usage() {
printf "%s - настройка astra-ca\n" ${0##*/}
printf "Использование: %s [<ключи>]\n" ${0##*/}
printf "Ключи:\n"
printf " -h, --help            Вывести этоу справку\n"
printf " -s <subsystem>        Название подсистемы (CA, KRA, OCSP, TKS, или TPS)\n"
printf " -f <file>             Полный путь к конфигурационному файлу\n"
printf " -v, --verbose         Run in verbose mode\n"
printf " --debug               Run in debug mode\n"
printf " --precheck            Execute pre-checks and exit\n"
printf " --skip-configuration  skip configuration step\n"
printf " --skip-installation   skip installation step\n"
printf " --enforce-hostname    enforce strict hostname/FQDN checks\n"
printf " --with-maven-deps     Install Maven dependencies\n"
}

echo "---------------------------"
echo "$@"
echo "---------------------------"

subsystem="CA"

while [ -n "$1" ]; do
  case "${1}" in
    --help | -h) 
        usage
        exit 0
        ;;
    -s)
        subsystem=${2}
        ;;
    -f)
        config=${2}
        ;;
    --debug)
        debug=true
  esac
  shift
done
$debug && {
    echo debug=$debug
    echo susbsystem=$subsystem
    echo config=$config
}
if [[ -f $config ]]; then
    cp $config /etc/pki/astra-ca/$(basename ${config}).ini
    config=/etc/pki/astra-ca/$(basename ${config}).ini
    echo config file: $config
else
    config=/etc/pki/astra-ca/default.ini
fi
# втащить конфиг в переменные окружения
source <(grep = ${config} | sed 's/ *= */="/' | sed 's/$/"/')

$debug && {
   echo "--- Полученные от FreeIPA пароли ---"
   echo pki_admin_password: $pki_admin_password # 1..8
   echo pki_backup_password: $pki_backup_password # 1..8
   echo pki_client_pkcs12_password: $pki_client_pkcs12_password # 1..8
   echo pki_ds_password: $pki_ds_password # 1..8
   echo pki_security_domain_password: $pki_security_domain_password # пусто
   echo pki_server_database_password: $pki_server_database_password # пусто
   echo pki_ca_signing_cert_path: $pki_ca_signing_cert_path # пусто
   echo pki_ca_signing_csr_path: $pki_ca_signing_csr_path # пусто
}
# Create NSS DB
    mkdir -v -p /etc/pki/astra-ca/nssdb
    cat /dev/urandom | tr -dc A-Za-z0-9 | head -c20 > /etc/pki/astra-ca/nssdb/pwdfile.txt
    certutil -N -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt
    chown -R www-data:www-data /etc/pki/astra-ca/nssdb
# Generate CA key pair
    cat /dev/urandom | tr -dc A-Za-z0-9 | head -c20 > /etc/pki/astra-ca/nssdb/noisefile.txt
CA_SKID="0x$(echo $pki_ca_signing_subject_dn | sha1sum | cut -d' ' -f1)"
OCSP=$pki_default_ocsp_uri
$debug && {
echo "------------------------------------------------------"
echo "Generating Self Signed CA Signing Certificate with NSS"
echo "------------------------------------------------------"
echo CA_CKID=$CA_SKID
echo OCSP=$OCSP
}
echo -e "y\n\ny\ny\n${CA_SKID}\n\n\n\n${CA_SKID}\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -S -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -z /etc/pki/astra-ca/nssdb/noisefile.txt \
    -x \
    -s "$pki_ca_signing_subject_dn" \
    -n "$pki_ca_signing_nickname" \
    -k "$pki_ca_signing_key_type" \
    -g "$pki_ca_signing_key_size" \
    -m "$pki_ca_signing_serial_number" \
    -h "$pki_ca_signing_token" \
    -Z ${pki_ca_signing_key_algorithm/with*/}  \
    -v 240 \
    -2 -3 \
    --keyUsage digitalSignature,nonRepudiation,certSigning,crlSigning,critical \
    --extAIA \
    --extSKID \
    -t TC,C,C

certutil -L -d /etc/pki/astra-ca/nssdb -n "$pki_ca_signing_nickname" -a > /etc/pki/astra-ca/ca_signing.crt
$debug && {
echo "-----------------------------------"
echo "Generating OCSP Signing Certificate"
echo "-----------------------------------"
echo -CA_SKID ${CA_SKID}
echo    -s "$pki_ocsp_signing_subject_dn"
echo    -c "$pki_ca_signing_nickname"
echo     n "$pki_ocsp_signing_nickname"
echo    -h "$pki_ocsp_signing_token"
echo    -k "$pki_ocsp_signing_key_type"
echo    -g "$pki_ocsp_signing_key_size"
echo    -Z ${pki_ocsp_signing_key_algorithm/with*/}
}

echo -e "y\n${CA_SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -S -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -z /etc/pki/astra-ca/nssdb/noisefile.txt \
    -s "$pki_ocsp_signing_subject_dn" \
    -c "$pki_ca_signing_nickname" \
    -n "$pki_ocsp_signing_nickname" \
    -h "$pki_ocsp_signing_token" \
    -k "$pki_ocsp_signing_key_type" \
    -g "$pki_ocsp_signing_key_size" \
    -Z ${pki_ocsp_signing_key_algorithm/with*/} \
    -v 24 \
    -m 2 \
    -3 \
    --extAIA \
    --extKeyUsage ocspResponder \
    --extGeneric 1.3.6.1.5.5.7.48.1.5:not-critical:/dev/null \
    -t u,u,u

certutil -L -d /etc/pki/astra-ca/nssdb -n "$pki_ocsp_signing_nickname" -a > /etc/pki/astra-ca/oscp_signing.crt

$debug && {
echo "------------------------------------------------------"
echo "Generating subsystem CA certificate with NSS"
echo "------------------------------------------------------"
echo CA_CKID=$CA_SKID
echo OCSP=$OCSP
echo -s "$pki_subsystem_subject_dn"
echo -c "$pki_ca_signing_nickname"
echo _n "$pki_subsystem_nickname"
echo -h "$pki_subsystem_token"
echo -k "$pki_subsystem_key_type"
echo -g "$pki_subsystem_key_size"
echo -Z ${pki_subsystem_key_algorithm/with*/}
}

echo -e "y\n${CA_SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -S -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -z /etc/pki/astra-ca/nssdb/noisefile.txt \
    -s "$pki_subsystem_subject_dn" \
    -c "$pki_ca_signing_nickname" \
    -n "$pki_subsystem_nickname" \
    -h "$pki_subsystem_token" \
    -k "$pki_subsystem_key_type" \
    -g "$pki_subsystem_key_size" \
    -Z ${pki_subsystem_key_algorithm/with*/} \
    -v 24 \
    -m 4 \
    --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature,nonRepudiation \
    --extKeyUsage clientAuth,serverAuth \
    -3 \
    --extAIA \
    -t u,u,u

certutil -L -d /etc/pki/astra-ca/nssdb -n "$pki_subsystem_nickname" -a > /etc/pki/astra-ca/subsystem.crt && 

# -----
mkdir -p /var/lib/pki/pki-tomcat/alias/
pk12util -d /etc/pki/astra-ca/nssdb -o /var/lib/pki/pki-tomcat/alias/ca_backup_keys.p12 -n "$pki_subsystem_nickname" \
    -k /etc/pki/astra-ca/nssdb/pwdfile.txt -W $pki_client_pkcs12_password #/etc/pki/astra-ca/nssdb/pwdfile.txt


$debug && {
echo "--List the keys and certificates in ca_backup_keys.p12 file"
pk12util -l /var/lib/pki/pki-tomcat/alias/ca_backup_keys.p12 -W $pki_client_pkcs12_password
echo "pk12util -> " $?
}


$debug && {
echo "------------------------------------------------------"
echo "Generating audit signing CA certificate with NSS"
echo "------------------------------------------------------"
echo CA_CKID=$CA_SKID
echo OCSP=$OCSP
echo -s "$pki_audit_signing_subject_dn"
echo -c "$pki_ca_signing_nickname"
echo _n "$pki_audit_signing_nickname"
echo -h "$pki_audit_signing_token"
echo -k "$pki_audit_signing_key_type"
echo -g "$pki_audit_signing_key_size"
echo -Z ${pki_audit_signing_key_algorithm/with*/}
}
echo -e "y\n${CA_SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -S -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -z /etc/pki/astra-ca/nssdb/noisefile.txt \
    -s "$pki_audit_signing_subject_dn" \
    -c "$pki_ca_signing_nickname" \
    -n "$pki_audit_signing_nickname" \
    -h "$pki_audit_signing_token" \
    -k "$pki_audit_signing_key_type" \
    -g "$pki_audit_signing_key_size" \
    -Z ${pki_audit_signing_key_algorithm/with*/} \
    -v 24 \
    -m 5 \
    --keyUsage critical,digitalSignature,nonRepudiation \
    --extKeyUsage clientAuth,serverAuth \
    -3 \
    --extAIA \
    -t u,u,u

certutil -L -d /etc/pki/astra-ca/nssdb -n "$pki_audit_signing_nickname" -a > /etc/pki/astra-ca/audit_signing.crt
echo "certutil -L ->" $?

$debug && {
echo "---------------------------------"
echo "Generating SSL Server certificate"
echo "---------------------------------"
echo CA_CKID=$CA_SKID
echo OCSP=$OCSP
echo -s "$pki_sslserver_subject_dn"
echo -c "$pki_ca_signing_nickname"
echo _n "$pki_sslserver_nickname"
echo -h "$pki_sslserver_token"
echo -k "$pki_sslserver_key_type"
echo -g "$pki_sslserver_key_size"
echo -Z ${pki_sslserver_key_algorithm/with*/}
echo -8 $pki_hostname
}
echo -e "y\n${CA_SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -S -d /etc/pki/astra-ca/nssdb -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -z /etc/pki/astra-ca/nssdb/noisefile.txt \
    -s "$pki_sslserver_subject_dn" \
    -c "$pki_ca_signing_nickname" \
    -n "$pki_sslserver_nickname" \
    -h "$pki_sslserver_token" \
    -k "$pki_sslserver_key_type" \
    -g "$pki_sslserver_key_size" \
    -Z ${pki_sslserver_key_algorithm/with*/} \
    -v 24 \
    -m 3 \
    --keyUsage critical,dataEncipherment,digitalSignature,keyEncipherment \
    --extKeyUsage serverAuth \
    --nsCertType sslServer \
    -8 "$pki_security_domain_hostname" \
    -3 \
    --extAIA \
    -t u,u,u

certutil -L -d /etc/pki/astra-ca/nssdb -n "$pki_sslserver_nickname" -a > /etc/pki/astra-ca/sslserver.crt
echo "certutil -S ->" $?

$debug && {
   echo "--------------"
   echo "Create ldap db"
   echo "--------------"
   echo pki_ds_base_dn: $pki_ds_base_dn # o=ipaca
   echo pki_ds_bind_dn: $pki_ds_bind_dn # cn=Directory Manager
   echo pki_ds_password: $pki_ds_password # 1..8
}


ldbm.py $pki_ds_base_dn "$pki_ds_bind_dn" $pki_ds_password
echo "ldbm.py ->" $?


ldapadd -v -D "$pki_ds_bind_dn" -w $pki_ds_password -f /etc/pki/schema.ldif
echo "ldapadd schema.ldif ->" $?

sed -e "s/{rootSuffix}/$pki_ds_base_dn/g" /etc/pki/db.ldif | ldapadd -v -D "$pki_ds_bind_dn" -w $pki_ds_password
echo "ldapadd db.ldif ->" $?

sed -e "s/{rootSuffix}/$pki_ds_base_dn/g" /etc/pki/acl.ldif | ldapadd -v -D "$pki_ds_bind_dn" -w $pki_ds_password
echo "ldapadd acl.ldif ->" $?


$debug && {
echo "-----------------------------------"
echo "Generating httpd Server certificate"
echo "-----------------------------------"
echo CA_CKID=$CA_SKID # 0xcd0404bce8bd875b1e533e0458e3abd6955ab176
echo OCSP=$OCSP # http://ipa-ca.testdomain.test/ca/ocsp
echo -c "$pki_ca_signing_nickname" # caSigningCert cert-pki-ca
echo ${pki_dns_domainname^^} # TESTDOMAIN.TEST
echo ${pki_hostname} # ipasrv.testdomain.test
tmp=${OCSP#*//}
ocsp_hostname=${tmp%%/*} # ipa-ca.testdomain.test
echo -8 $pki_security_domain_hostname,$ocsp_hostname # ipasrv.testdomain.test,ipa-ca.testdomain.test

}
openssl genrsa -out httpd.key 2048
openssl req -key httpd.key -new -sha256 -subj "/O=${pki_dns_domainname^^}/CN=${pki_hostname}" -out httpd.csr -outform DER \
    -addext "subjectKeyIdentifier = hash"
#-addext "subjectAltName = otherName:1.3.6.1.5.2.2;UTF8:HTTP/ipasrv.testdomain.test@TESTDOMAIN.TEST"

echo -e "y\n${CA_SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
  certutil -C -d /etc/pki/astra-ca/nssdb  \
    -f /etc/pki/astra-ca/nssdb/pwdfile.txt \
    -i httpd.csr \
    -o httpd.der \
    -c "$pki_ca_signing_nickname" \
    -Z SHA256 \
    -v 24 \
    -m 9 \
    --keyUsage critical,dataEncipherment,digitalSignature,keyEncipherment,nonRepudiation \
    --extKeyUsage serverAuth,clientAuth \
    -8 "$pki_security_domain_hostname",$ocsp_hostname \
    -3 \
    --extAIA \
echo "certutil -C ->" $?
# NOTE: возможно сгенерировать сертификат целиком с исп. -S
openssl x509 -in httpd.der -out httpd.crt -outform PEM
echo $?
cp httpd.crt /var/lib/ipa/certs/httpd.crt
echo $?
cp httpd.key /var/lib/ipa/private/httpd.key
echo $?
cp /etc/pki/astra-ca/ca_signing.crt /etc/ipa/ca.crt
echo $?

mkdir -p /var/lib/pki/pki-tomcat/conf/ca/
cp /etc/pki/astra-ca/CS.cfg /var/lib/pki/pki-tomcat/conf/ca/
echo "copy CS.cfg" $?

systemctl stop apache2
echo -e "#astra-ca pkispawn\n<IfModule ssl_module>\n\tListen 8443\n</IfModule>\n" >> /etc/apache2/ports.conf
echo -e "#astra-ca pkispawn\nListen 8080\n" >> /etc/apache2/ports.conf
systemctl start apache2
echo start apache2 $?
