#!/usr/bin/python3 -i

import configparser
import pprint

def get_cert_template(ini_file):
    """Распарсить ini-файл"""
    ini = configparser.RawConfigParser()
    ini.read(ini_file)
    result = {}
    for section in ini.sections():
        for name in ini.options(section):
            result[name] = ini.get(section, name)
    return result

#conf = "caUserCert.cnf"
conf = "conf.ini"
pprint.pprint(get_cert_template(conf))
