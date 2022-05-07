from threading import Thread
import pickle
from dnslib import *
import Recourse

PORT = 53
HOST = '127.0.0.1'
DNS_HOST = '8.26.56.26'  # для подключения host dns, которому мы отправляем запросы, когда не знаем кэщ
cash = {}
is_alive = True
flag = False
default_ttl = 20  # сколько хранить запросы


def save():  # сохранение кэша
    with open("save.pickle", "wb") as write_file:
        pickle.dump(cash, write_file)


def load():  # загрузка кэша
    global cash, default_ttl
    with open("save.pickle", "rb") as read_file:
        cash = pickle.load(read_file)


def send_request_to_dns(dns_server, p):  # запрос нашему серверу на обработку запросов клиентов
    try:
        dns_server.send(p)
        p2, a2 = dns_server.recvfrom(1024)
        print('Отправлен запрос локальному днс серверу')

        return p2
    except:
        print('Днс сервер не отвечает')
        return


def format_dns_answer(name, clas, _type, ttl, data):
    return dns.RR(rname=name,
                  rclass=clas,
                  rtype=_type,
                  ttl=ttl,
                  rdata=data)


def start_server():
    global cash, is_alive, flag, default_ttl

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:

            server.bind((HOST, PORT))
            server.settimeout(10)  # если в течении 10 секунд запросов не было, мы логируем это и продолжаем ждать
            dns_server.connect((DNS_HOST, PORT))  # подлючаемся к серверу, который будет разрешать наши вопросы
            dns_server.settimeout(10)

            print('Сервер запущен')

            while True:  # пока сервер жив, крутимся в бесконечном цикле
                while is_alive:

                    try:
                        client_req, client_address = server.recvfrom(1024)  # получаем запрос
                        client_data = DNSRecord.parse(client_req)  # вытаскиваем из запроса данные

                        print(f'Пришел запрос:{client_data.q.qname}  '
                              f'{client_data.q.qtype}')
                    except:
                        print('В течение 10 секунд запросы не поступали')
                        continue

                    flag = True

                    if str(client_data.q.qname) in cash:  # если в кэше есть запрос клиента

                        recourse = cash.get(str(client_data.q.qname))
                        query = client_data.reply()
                        if client_data.q.qtype == QTYPE.A and recourse.A:  # сверяем тип запроса
                            flag = False
                            for address in recourse.A:  # составляем ответ
                                query.add_answer(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                                   QTYPE.A, default_ttl, A(address.data)))

                            for ns in recourse.NS:  # записываем ns сервера
                                query.add_auth(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                                 QTYPE.NS, default_ttl, NS(ns.label)))

                            for e in recourse.NSA:  # NSAdress записываются ip адреса ns серверов
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.A, default_ttl, A(nsA.data)))

                                if len(nsA.data) == 16:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.AAAA, default_ttl, AAAA(nsA.data)))

                        elif client_data.q.qtype == QTYPE.AAAA and recourse.AAAA:
                            flag = False
                            for address in recourse.AAAA:
                                query.add_answer(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                                   QTYPE.AAAA, default_ttl, AAAA(address.data)))

                            for ns in recourse.NS:
                                query.add_auth(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                                 QTYPE.NS, default_ttl, NS(ns.label)))

                            for e in recourse.NSA:  # NSAdress записываются ip адреса ns серверов
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.A, default_ttl, A(nsA.data)))

                                if len(nsA.data) == 16:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.AAAA, default_ttl, AAAA(nsA.data)))

                        elif client_data.q.qtype == QTYPE.PTR and recourse.PTR:
                            flag = False
                            query.add_auth(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                             QTYPE.SOA, default_ttl, recourse.PTR))

                        elif client_data.q.qtype == QTYPE.NS and recourse.NS:
                            flag = False

                            for ns in recourse.NS:
                                query.add_answer(format_dns_answer(client_data.q.qname, client_data.q.qclass,
                                                                   QTYPE.NS, default_ttl, NS(ns.data)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.A, default_ttl, A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(format_dns_answer(ns.label, client_data.q.qclass,
                                                                   QTYPE.AAAA, default_ttl, AAAA(nsA.data)))
                        else:
                            server_packet = send_request_to_dns(dns_server, client_req)
                            server_data: DNSRecord = DNSRecord.parse(
                                server_packet)
                            cash.get(str(client_data.q.qname)).addRecourse(
                                server_data)
                            print("Закешировал")
                            server.sendto(server_packet, client_address)
                            print('Отправил ответ')
                            continue

                    if flag:  # если в кэше нет соответствующей записи, то мы должны ее добавить

                        # отправляем запрос нашему днс серверу, который нас обслуживает
                        server_packet = send_request_to_dns(dns_server, client_req)

                        server_data = DNSRecord.parse(server_packet)  # парсим

                        # создаем новую ресурсную запись
                        cash[str(client_data.q.qname)] = Recourse.Recourse(str(client_data.q.qname))

                        cash.get(str(client_data.q.qname)).addRecourse(server_data)

                        print(f'Закешировал: {client_data.q.qname}  '
                              f'{client_data.q.qtype}')

                        server.sendto(server_packet, client_address)

                        print('Отправил ответ')

                    else:  # если ресурсная запись есть, то отправлем ответ, который был сформирован, клиенту
                        server.sendto(query.pack(), client_address)  # формируем пакет из кэша
                        print(f"Отправил закешированный пакет:  "
                              f"{client_data.q.qname}  {client_data.q.qtype}")

                # при отключении сервера
                save()  # сохраняет кэш
                cash = {}
                print('Сохранил кеш')
                print('Сервер выключен')
                while not is_alive:
                    time.sleep(5)
                print('Сервер запущен')
                load()  # когда снова запустится загрузит кэш и будет работать
                print('Загрузил сj')


def main():
    global is_alive
    Thread(target=start_server).start()
    while True:
        is_alive = True  # запуск и выключение сервера
        while input() != 'q':
            continue
        is_alive = False
        while input() != 's':
            continue


if __name__ == '__main__':
    main()
