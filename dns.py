import re
import sys
import os
from twisted.names import client, dns, server, hosts as hosts_module, root, cache, resolve
from twisted.internet import reactor
from twisted.python.runtime import platform
import time
import socket, struct
from threading import Thread

DELAY = 60*60*4 #Задержка обновлений списка банов
DELAY_CLEAR = 60
WHITE_LIST = ["127.0.0.1"]
rkn = []
BAN = []


def ip2long(ip):
    """
    Convert an IP string to long
    """
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    except Exception:
        return None


def check_rkn(ip, rkn):
    rkn_mask = int(rkn["mask"])
    rkn_ip = str(rkn["ip"])
    try:
        return (ip2long(ip) & (-1 << (32 - rkn_mask)) ) == ip2long(rkn_ip)
    except Exception:
        return None


def razbor_net(cur_ip_adrr, ip_array):
    flag = False
    for cur_cidr in ip_array:
        if check_rkn(cur_ip_adrr, cur_cidr) is True:
            flag = True
    return flag


def search_file_for_all(hosts_file, name):
    results = []
    try:
        lines = hosts_file.getContent().splitlines()
    except:
        return results

    name = name.lower()
    for line in lines:
        idx = line.find(b'#')
        if idx != -1:
            line = line[:idx]
        if not line:
            continue
        parts = line.split()
        for domain in [s.lower() for s in parts[1:]]:
            if (domain.startswith(b'/') and domain.endswith(b'/') and
                    re.search(domain.strip('/'), name.lower())) or name.lower() == domain.lower():
                results.append(hosts_module.nativeString(parts[0]))
    return results


class Resolver(hosts_module.Resolver):

    def _aRecords(self, name):
        return tuple([
            dns.RRHeader(name, dns.A, dns.IN, self.ttl, dns.Record_A(addr, self.ttl))
            for addr in search_file_for_all(hosts_module.FilePath(self.file), name)
            if hosts_module.isIPAddress(addr)
        ])


def create_resolver(servers=None, resolvconf=None, hosts=None):
    if platform.getType() == 'posix':
        if resolvconf is None:
            resolvconf = b'/etc/resolv.conf'
        if hosts is None:
            hosts = b'/etc/hosts'
        the_resolver = client.Resolver(resolvconf, servers)
        host_resolver = Resolver(hosts)
    else:
        if hosts is None:
            hosts = r'c:\windows\hosts'
        from twisted.internet import reactor
        bootstrap = client._ThreadedResolverImpl(reactor)
        host_resolver = Resolver(hosts)
        the_resolver = root.bootstrap(bootstrap, resolverFactory=client.Resolver)

    return resolve.ResolverChain([host_resolver, cache.CacheResolver(), the_resolver])

class MyDNSServerFactory(server.DNSServerFactory):
    clear = int(time.time())
    allow = {}
    disallowed = []

    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        resolvers = []
        if authorities is not None:
            resolvers.extend(authorities)
        if caches is not None:
            resolvers.extend(caches)
        if clients is not None:
            resolvers.extend(clients)

        self.canRecurse = not not clients
        self.resolver = resolve.ResolverChain(resolvers)
        self.verbose = verbose
        if caches:
            self.cache = caches[-1]
        self.connections = []

        print("[i] DNS сервер запущен")

    def gotResolverResponse(self, response, protocol, message, address):
        qname = message.queries[0].name.name
        ans, auth, add = response
        response = self._responseFromMessage(
            message=message, rCode=dns.OK,
            answers=ans, authority=auth, additional=add)
        #print("Checking host: ", qname.decode('UTF-8'), "from ", address)
        print("Checking host: ", qname.decode('UTF-8'), "from <hidden>")
        temp_ans = []
        for i in ans:
            temp_ans.append(i)
        temp_ans_pl = []
        for i in ans:
            temp_ans_pl.append(i.payload)
        for answer in ans[:]:
            if answer.type != dns.A:
                continue
            ip = socket.inet_ntoa(answer.payload.address)
            in_out = razbor_net(ip, rkn)
            if in_out is False:
                print("[ CLEAN ]> ", ip)
            elif in_out is True:
                print("[ DIRTY ]> ", ip)
                if len(ans) > 1:
                    ans.remove(answer)
                else:
                    ans.remove(answer)
                    # # Вернуть все IP
                    # for i in temp_ans:
                    #     ans.append(i)
                    # for i in ans:
                    #     i.payload = temp_ans_pl[0]
                    #     temp_ans_pl.pop(0)

        self.sendReply(protocol, response, address)

        l = len(ans) + len(auth) + len(add)
        self._verboseLog("Lookup found %d record%s" % (l, l != 1 and "s" or ""))

        if self.cache and l:
            self.cache.cacheResult(
                message.queries[0], (ans, auth, add)
            )

    def handleQuery(self, message, protocol, address):
        query = message.queries[0]
        # Очистка счетчика
        if int(time.time()) - self.clear > DELAY_CLEAR:
            self.allow = {}
            self.clear = int(time.time())
        # Счетчик запросов
        if self.allow.get(address[0]) is None:
            self.allow[address[0]] = 1

        # Бан IP при привышении порога в 400 запросов в DELAY_CLEAR
        if self.allow.get(address[0]) > 400 and address[0] not in self.disallowed and address[0] not in WHITE_LIST:
            self.disallowed.append(address[0])

        if address[0] in self.disallowed:
            print("Banned")
            return None

        # При привышении 200 запросов в DELAY_CLEAR отключение TXT|ANY запросов
        if self.allow.get(address[0]) > 200 and (query.type == 16 or query.type == 255) and address[0] not in WHITE_LIST:
            print("Block ALL TXT")
            return self.sendReply(protocol, message, address)

        self.allow[address[0]] += 1
        return self.resolver.query(query).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )

def update_ip_tables():
    cmd = "sh {}/network.sh".format(here)
    os.system(cmd)

def update_bans():
    f = BAN
    rkn.clear()
    for net in f:
        rkn.append({"ip": net.split("/")[0], "mask": net.split("/")[1].replace("\n", "")})


def make_ban():
    try:
        cmd = "curl -s https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv | cut -d ';' -f 1 |  tr '|' '\n' | grep '/' | tr -d ' ' | sort -k1 -n"
        for i in os.popen(cmd).read().split('\n'):
            BAN.append(i)
        BAN.remove("")
    except:
        return False

class DownloadThread(Thread):
    def __init__(self):
        """Инициализация потока"""
        Thread.__init__(self)
        self.now = int(time.time())


    def run(self):
        """Запуск потока"""
        while True:
            if int(time.time()) - self.now > DELAY:
                print("[i] Чтение новых записей")
                if make_ban() is not False:
                    update_bans()# pass
                    self.now = int(time.time())
                    print("[i] Записи о заблокированых подсетях обновлены")
                else:
                    print("[W] Записи о заблокированых подсетях НЕ обновлены")


def main(port):
    print("[i] Скачиваем список заблокированых адресов")
    if make_ban() is False:
        print("[!] Скачивание не удалось! Выход из программы!")
        os._exit(0)
        print("[i] Список заблокированих адресов получен")
    print("[i] Чтение записей о блокировке")
    update_bans()
    print("[i] Записи о заблокированых подсетях обновлены")
    print("[i] Запускаем поток обновлений")
    thread = DownloadThread()
    thread.start()
    print("[i] Запускаем DNS сервер")
    factory = MyDNSServerFactory(
        clients=[create_resolver(servers=[('1.1.1.1', 53)], hosts='hosts')], verbose=0,
    )
    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(port, protocol)
    reactor.listenTCP(port, factory)
    reactor.run()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        port = 53
    else:
        port = int(sys.argv[1])
    raise SystemExit(main(port))
