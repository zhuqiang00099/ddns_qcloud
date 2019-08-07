# -*- coding: utf8 -*-
import base64
import hashlib
import hmac
import time
import random
import requests
import logging

jsonlib = __import__('json')
secret_id = ""
secret_key = ""


def get_string_to_sign(method, endpoint, params):
    s = method + endpoint + "?"
    query_str = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    return s + query_str

def sign_str(key, s, method):
    hmac_str = hmac.new(key.encode("utf8"), s.encode("utf8"), method).digest()
    return base64.b64encode(hmac_str)


def get_recordList(domain:str,subDmain:str):
    endpoint = "cns.api.qcloud.com/v2/index.php"
    data = {
        'Action': 'RecordList',
        'Nonce': random.randint(1, 65536),
        'Region': 'ap-guangzhou',
        'SecretId': secret_id,
        'Timestamp': int(time.time()),
        'domain': domain,
        'subDomain': subDmain
    }
    s = get_string_to_sign("GET", endpoint, data)
    data["Signature"] = sign_str(secret_key, s, hashlib.sha1)
    resp = requests.get("https://" + endpoint + '?', params=data)
    info = jsonlib.loads(resp.text)
    return info

def set_record(domain:str,subDmain:str,recordId:int,ip:str,recordType:str = 'A',recordLine:str='默认',ttl:int=600):
    endpoint = "cns.api.qcloud.com/v2/index.php"
    data = {
        'Action': 'RecordModify',
        'Nonce': random.randint(1,65536),
        'Region': 'ap-guangzhou',
        'SecretId': secret_id,
        'Timestamp': int(time.time()),
        'domain': domain,
        'subDomain': subDmain,
        'recordId': recordId,
        'recordType': recordType,
        'recordLine': recordLine,
        'value': ip,
        'ttl': ttl

    }
    s = get_string_to_sign("GET", endpoint, data)
    data["Signature"] = sign_str(secret_key, s, hashlib.sha1)
    resp = requests.get("https://" + endpoint + '?', params=data)
    info = jsonlib.loads(resp.text)
    try:
        if info['code'] == 0:
            logging.info("域名记录修改成功，指向->{}".format(ip))
        else:
            logging.info("域名记录修改失败，错误码:{},错误信息:{}".format(info['code'],info['message']))
    except KeyError:
        logging.info('域名记录修改请求发生错误，resp内容:{}'.format(info))

def get_id_ip_from_info(info,subDomain):
    record_id = next(x['id'] for x in info['data']['records'] if x['name'] == subDomain and x['line'] == u'默认')
    ip = next(x['value'] for x in info['data']['records'] if x['name'] == subDomain and x['line'] == u'默认')
    return record_id,ip

def get_new_ip():
    return requests.get(url='http://members.3322.org/dyndns/getip').text


logging.basicConfig(filename="ddns.log", filemode="w", format="%(asctime)s %(name)s:%(levelname)s:%(message)s", datefmt="%d-%M-%Y %H:%M:%S", level=logging.INFO)
if __name__ == '__main__':

    check_interval = 30
    domain = ''
    subDomain = ''
    while 1:
        info = get_recordList(domain, subDomain)
        record_id, ip = get_id_ip_from_info(info,subDomain)
        new_ip = get_new_ip()
        if new_ip.strip() != ip.strip():
            set_record(domain,subDomain,record_id,new_ip)
        else:
            logging.info('域名记录ip地址与当前ip一致，无需修改，当前ip地址:{}'.format(new_ip))
        time.sleep(check_interval)

    #check ip



