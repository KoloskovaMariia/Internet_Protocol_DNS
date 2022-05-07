from socket import *
from dnslib import *

PORT = 53
HOST = '127.0.0.1'

with socket.socket(socket.AF_INET, SOCK_DGRAM) as client:
    client.connect((HOST, PORT))
    request = input()
    while request != 'q':
        s = request.split(' ')
        req = 0
        if len(s) > 1:
            if s[1] == "A":
                req = DNSRecord(q=DNSQuestion(s[0], QTYPE.A))
            elif s[1] == "AAAA":
                req = DNSRecord(q=DNSQuestion(s[0], QTYPE.AAAA))
            elif s[1] == "NS":
                req = DNSRecord(q=DNSQuestion(s[0], QTYPE.NS))
            elif s[1] == "PTR":
                req = DNSRecord(q=DNSQuestion(s[0], QTYPE.PTR))
            else:
                print("Неверный тип запроса")
                request = input()
                continue
        elif len(s) == 1:
            req = DNSRecord(q=DNSQuestion(s[0], QTYPE.A))
        else:
            print("Неверный тип запроса")
            request = input()
            continue
        client.send(req.pack())
        m, a = client.recvfrom(1024)
        print(DNSRecord.parse(m))
        request = input()
    client.close()
