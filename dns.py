import os
import re
import socket
import struct
import sys
import time
from threading import Thread

from twisted.internet import reactor
from twisted.names import client, dns, server, hosts as hosts_module, root, cache, resolve
from twisted.python.runtime import platform

DELAY = 60 * 60 * 4  # Задержка обновлений списка банов в секундах (4 часа)
DELAY_CLEAR = 60
WHITE_LIST = ["127.0.0.1"]
BAN = []
rkn_array = {}
rkn_array_tmp = {}
first_start = True

for mask in range(32, -1, -1):  # Fill from 32 to 0
    rkn_array[mask] = {}
    rkn_array_tmp[mask] = {}


def ip2long(ip):
    """
    Convert an IP string to long
    """
    try:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    except Exception:
        return None


def razbor_net(inputAddress_long):
    try:
        for mask in range(32, -1, -1):
            # print("Mask: ", mask)
            inputAddress_long_masked = inputAddress_long & (-1 << (32 - mask))
            if rkn_array[mask].get(inputAddress_long_masked) is True:
                # print("True")
                return True
            else:
                if mask is 0:
                    # print("None")
                    return None
    except Exception as e:
        print("Exception: ", e, " Address: ", inputAddress_long)
        return None
    return False


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
#       print("Checking host: ", qname.decode('UTF-8'), "from ", address)
#		print("Checking host: ", qname.decode('UTF-8'), "from <hidden>")
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
            in_out = razbor_net(ip2long(ip))
            if in_out is None:
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
        if self.allow.get(address[0]) > 200 and (query.type == 16 or query.type == 255) and address[
            0] not in WHITE_LIST:
            print("Block ALL TXT")
            return self.sendReply(protocol, message, address)

        self.allow[address[0]] += 1
        return self.resolver.query(query).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )


def apply_block_records():
    global rkn_array, rkn_array_tmp
    f = BAN
    for net in f:
        try:
            net = net.replace(" ", "")
            mask = int(net.split("/")[1].replace("\n", ""))
            address_long = int(ip2long(net.split("/")[0].replace("\n", "")))
            if mask in rkn_array_tmp:
                rkn_array_tmp[mask][address_long] = True
            else:
                rkn_array_tmp[mask] = {}
                rkn_array_tmp[mask][address_long] = True
        except Exception:
            # print (rkn_array_tmp)
            print("Warning: can't process: `", net, "`")
            return False
    rkn_array = rkn_array_tmp.copy()
    rkn_array_tmp.clear()
    BAN.clear()
    for mask in range(32, -1, -1):  # Fill from 32 to 0
        rkn_array_tmp[mask] = {}
    return True


def download_block_records():
    """
    # Никогда не вернет False
    # Нужно проверять код выхода при выполнении cmd и вызывать return False, если код !=0
    """
    try:
        cmd = "curl -s https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv | cut -d ';' -f 1 |  tr '|' '\n' | grep '/' | tr -d ' ' | sort -k1 -n | uniq"
        cmd3 = "curl -s https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv | cut -d ';' -f 1 |  tr '|' '\n' | grep -v '/' | grep -oE \"\\b([0-9]{1,3}\.){3}[0-9]{1,3}\\b\" | tr -d ' ' | sort -k1 -n | uniq | awk '{print $1\"/32\"}'"

        for i in os.popen(cmd).read().split('\n'):
            BAN.append(i)
        BAN.remove("")
        for i in os.popen(cmd3).read().split('\n'):
            BAN.append(i)
        BAN.remove("")
    except Exception:
        return False


class DownloadThread(Thread):
    def __init__(self):
        """Инициализация потока"""
        Thread.__init__(self)
        self.now = int(time.time())

    def run(self):
        """Запуск потока"""
        global first_start
        if first_start is True:
            first_start = False
            time.sleep(DELAY)
        while True:
            print("[i] Чтение новых записей")
            if download_block_records() is not False:
                apply_block_records()  # pass
                print("[i] Записи о заблокированных подсетях обновлены")
                time.sleep(DELAY)
            else:
                print("[W] Записи о заблокированных подсетях НЕ обновлены")
                time.sleep(DELAY)


def main(port):
    print("[i] Скачиваем список заблокированных адресов")
    if download_block_records() is False:
        print("[!] Скачивание не удалось! Выход из программы!")
        os._exit(0)
    print("[i] Список заблокированных адресов получен")
    print("[i] Чтение записей о блокировке")
    apply_block_records()
    print("[i] Записи о заблокированных подсетях обновлены")
    print("[i] Запускаем поток обновлений")
    thread = DownloadThread()
    thread.start()
    print("[i] Запускаем DNS сервер")
    factory = MyDNSServerFactory(
        clients=[create_resolver(servers=[('1.1.1.1', 53)], hosts='hosts')], verbose=0,
    )
    protocol = dns.DNSDatagramProtocol(controller=factory)

    import signal

    def custom_handler(signum, stackframe):
        # print("Got signal: %s" % signum)
        reactor.callFromThread(reactor.stop)  # to stop twisted code when in the reactor loop

    def stop_function():
        print("\nStop")
        os._exit(0)

    reactor.listenUDP(port, protocol)
    reactor.listenTCP(port, factory)
    signal.signal(signal.SIGINT, custom_handler)
    reactor.addSystemEventTrigger('after', 'shutdown', stop_function)
    reactor.run()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        port = 53
    else:
        port = int(sys.argv[1])
    raise SystemExit(main(port))
