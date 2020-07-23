#!/usr/bin/env python3

import argparse
from elastictabstops import Table
import math
import random
import socket
from struct import pack, unpack

# 問い合わせまたは応答
QR = {
    "QUERY": 0,
    "RESPONSE": 1
}

def get_qr_info(num):
    if num == QR["QUERY"]:
        return "Query"
    elif num == QR["RESPONSE"]:
        return "Response"
    else:
        return "Undefined"

# 問い合わせの種類
OPCODE = {
    "QUERY": 0, # 通常の照会
    "IQUERY": 1, # 逆照会
    "STATUS": 2, # ステータス
    "UNASSIGNED": 3,
    "NOTIFY": 4, # 通知
    "UPDATE": 5 # 更新
}

def get_opcode_info(num):
    if num == QR["QUERY"]:
        return "Query"
    elif num == QR["IQUERY"]:
        return "IQuery"
    elif num == QR["STATUS"]:
        return "Status"
    elif num == QR["UNASSIGNED"]:
        return "Unassigned"
    elif num == QR["NOTIFY"]:
        return "Notify"
    elif num == QR["UPDATE"]:
        return "Update"
    else:
        return "Undefined"

# Authoritative Answerかどうか
AA = {
    False: 0,
    True: 1
}

def get_aa_info(num):
    if num == AA[True]:
        return "Yes"
    elif num == AA[False]:
        return "No"
    else:
        return "Undefined"

# Truncateが発生したかどうか
TC = {
    "NOT_TRUNCATED": 0,
    "TRUNCATED": 1
}

def get_tc_info(num):
    if num == TC["TRUNCATED"]:
        return "Truncated"
    elif num == TC["NOT_TRUNCATED"]:
        return "Not truncated"
    else:
        return "Undefined"

# 問い合わせ先種別
RD = {
    "AUTHORITATIVE_SERVER": 0,
    "FULL_SERVICE_RESOLVER": 1
}

def get_rd_info(num):
    if num == RD["AUTHORITATIVE_SERVER"]:
        return "Authoritative Server"
    elif num == RD["FULL_SERVICE_RESOLVER"]:
        return "Full service resolver"
    else:
        return "Undefined"

# 名前解決可能かどうか
RA = {
    True: 0,
    False: 1
}

def get_ra_info(num):
    if num == RA[True]:
        return "Yes"
    elif num == RA[False]:
        return "No"
    else:
        return "Undefined"

# レスポンスコード
RCODE = {
    "NO_ERROR": 0,
    "FORM_ERROR": 1,
    "SERV_FAIL": 2,
    "NX_DOMAIN": 3, # 問い合わせされた名前が見つからない
    "NOT_IMP": 4,
    "REFUSED": 5
}

def get_rcode_info(num):
    if num == RCODE["NO_ERROR"]:
        return "No error"
    elif num == RCODE["FORM_ERROR"]:
        return "Format error"
    elif num == RCODE["SERV_FAIL"]:
        return "Server failure"
    elif num == RCODE["NX_DOMAIN"]:
        return "Not found"
    elif num == RCODE["NOT_IMP"]:
        return "Not implemented"
    elif num == RCODE["REFUSED"]:
        return "Connection refused"
    else:
        return "Undefined"

TYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28
}

def get_type_info(num):
    if num == TYPE["A"]:
        return "A"
    elif num == TYPE["NS"]:
        return "NS"
    elif num == TYPE["CNAME"]:
        return "CNAME"
    elif num == TYPE["SOA"]:
        return "SOA"
    elif num == TYPE["MX"]:
        return "MX"
    elif num == TYPE["TX"]:
        return "TX"
    elif num == TYPE["AAAA"]:
        return "AAAA"
    else:
        return "Undefined"

CLASS = {
    "IN": 1
}

def get_class_info(num):
    if num == CLASS["IN"]:
        return "IN"
    else:
        return "Undefined"

# 初回に見に行くDNSホスト
DEFAULT_DNS_HOST = "8.8.8.8"

# リクエストヘッダを返す
def make_header():
    id = pack('!H', math.ceil(random.uniform(0x0000, 0xFFFF)))
    qr = QR["QUERY"]
    opcode = OPCODE["QUERY"]
    aa = AA[False]
    tc = TC["NOT_TRUNCATED"]
    rd = RD["FULL_SERVICE_RESOLVER"]
    ra = RA[True]
    rcode = RCODE["NO_ERROR"]

    flag = pack('!H', (qr << 15) +
                      (opcode << 11) +
                      (aa << 10) +
                      (tc << 9) +
                      (rd << 8) +
                      (ra << 7) +
                      (0 << 4) + # 予約bit
                      rcode)
    qd_count = pack('!H', 1) # 質問の数
    an_count = pack('!H', 0) # 回答の数
    ns_count = pack('!H', 0) # Authorityの数
    ar_count = pack('!H', 0) # 追加情報の数

    return id + flag + qd_count + an_count + ns_count + ar_count

# Question部のバイト列を返す
def make_question(fqdn):
    qname = make_qname(fqdn)
    qtype = pack('!H', TYPE["A"])
    qclass = pack('!H', CLASS["IN"])

    return qname + qtype + qclass

# FQDNからバイト形式のQNAMEを返す
def make_qname(fqdn):
    labels = fqdn.split('.')
    converted_hostname = b''
    for label in labels:
        converted_hostname = converted_hostname + pack('!B', len(label)) + label.encode()
    return converted_hostname + pack('!B', 0)

# レスポンスヘッダに相当する箇所を抽出する
def parse_header(msg):
    parsed_msg = unpack('!6H', msg)
    id = parsed_msg[0]
    qr = (parsed_msg[1] >> 15) & 0x01
    opcode = (parsed_msg[1] >> 11) & 0x07
    aa = (parsed_msg[1] >> 10) & 0x01
    tc = (parsed_msg[1] >> 9) & 0x01
    rd = (parsed_msg[1] >> 8) & 0x01
    ra = (parsed_msg[1] >> 7) & 0x01
    rcode = parsed_msg[1] & 0x0f

    printable_table = [
        ["ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "RCODE", "QD", "AN", "NS", "AR"],
        [f'{id}', f'{get_qr_info(qr)}', f'{get_opcode_info(opcode)}',
        f'{get_aa_info(aa)}', f'{get_tc_info(tc)}', f'{get_rd_info(rd)}',
        f'{get_ra_info(ra)}', f'{get_rcode_info(rcode)}',
        f'{parsed_msg[2]}', f'{parsed_msg[3]}', f'{parsed_msg[4]}', f'{parsed_msg[5]}']
    ]
    print("# HEADER")
    print(Table(printable_table).to_spaces())

# Offsetやドメインを除くAnswerから、type, class, ttl, rdlengthを求める
def parse_answer(msg):
    answer_without_rdata = msg[:10]
    parsed_msg = unpack('!HHIH', answer_without_rdata)
    rd_length = parsed_msg[3]

    # IPv4アドレス
    if get_type_info(parsed_msg[0]) == "A":
        ipv4addr = msg[10:(10 + rd_length)]

    printable_table = [
        ["TYPE", "CLASS", "TTL", "IP_OR_FQDN"],
        [f'{get_type_info(parsed_msg[0])}', f'{get_class_info(parsed_msg[1])}', f'{parsed_msg[2]}', ".".join(map(str, unpack("!4B", ipv4addr)))]
    ]
    print("# ANSWER SECTION")
    print(Table(printable_table).to_spaces())

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument("fqdn", help="FQDN or IP addr", type=str)
    args = parser.parse_args()
    msg = make_header() + make_question(args.fqdn)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDPで見に行く
    s.connect((DEFAULT_DNS_HOST, 53))
    send_bytes = s.send(msg)
    if send_bytes == 0:
        print("送れてないで")
        exit(1)
    recv_bytes = s.recv(2048)
    # 固定長なので雑に取り出す
    header = recv_bytes[:12]
    parse_header(header)
    rest = recv_bytes[13:]
    rest_without_query = rest[len(make_question(args.fqdn)) - 1:]
    # offsetであればQuestionのFQDNを使い回す
    if rest_without_query[0:2] == b'\xc0\x0c':
        print(f'\nDomain: {args.fqdn}\n')
        rest_without_query = rest_without_query[2:]
    parse_answer(rest_without_query)
    s.close()

if __name__ == "__main__":
    main()
