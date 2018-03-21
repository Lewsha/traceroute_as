import argparse
import socket
import json
import urllib.request

"""Трассировщик автономных систем
!!!Для работы необходимо отключить брандмауэр windows
!!!В сети университета может не работать (наверняка не будет)

        Итак, идея!
    В заголовке пакета IP есть поле TTL (time to live), указывающее максимальное
количество промежуточных роутеров, через которые пройдет пакет. Если какой-нибудь 
роутер примет пакет с TTL равным 0, он ответит error пакетом по протоколу ICMP.
    То есть нам нужно установить TTL в 0. Далее в цикле увеличиваем TTL на 1,
пытаемся на указанный хост отправить icmp пакет с установленным TTL.
Принимаем ICMP пакет. В нем извлекаем адрес отправителя, если он совпал в адресом
назначеного хоста, то можно выходить из цикла, иначе продолжаем.
"""


def trace_as(dest_ip):
    """В цикле получаем следующий ip до тех пор, пока он не совпадет с нужным нам,
    либо пока не превысится лимит хопов (сделано так, потому что мы можем напороться на ситуацию,
    при которой путь до конца не протрассируется"""
    ip = None
    ttl = 0
    max_hop = 30
    while ip != dest_ip:
        ttl += 1
        ip = get_trace(dest_ip, ttl)
        """Если мы не смогли подрубиться по ip, печатаем одно"""
        if ip == '*':
            print("{}.\t{}\tWaiting interval exceeded".format(ttl - 1, ip))
        elif ip_is_white(ip):
            """Если подключились по белому ip, то все ок, забираем инфу"""
            print("{}.\t{}\t{}".format(ttl - 1, ip, get_info(ip)))
        else:
            """Если же ip  то не все ок"""
            print("{}.\t{}".format(ttl - 1, ip))
        if ttl == max_hop + 1:
            break


def get_info(ip):
    """Получаем данные об автономных системах, используя сайт ipinfo.io.
    Он получает получать данные по ip. Пожалуй, лучше было бы использовать whois,
    потому что он предоставляет, пожалуй, больше информации,
    но сайт за счет приписки "/json" дает возможность вытащить всю информацию в виде словаря,
    снимая необходимость парсить текстовый ответ whois сервака."""
    """Ну и да, раз данные с веб-страницы, то они в формате java script,
     поэтому используем json для распаковки"""
    data = json.loads(urllib.request.urlopen('http://ipinfo.io/{ip}/json'.format(ip=ip)).read())
    """Будем возвращать информацию сразу в виде строки"""
    info = ''
    """Приходится проверять наличие информации в словаре,
     потому что далеко не у всех ip сайт дает полные данныею
     (не знаю, косяк ли это сайта или косяк домена)"""
    for key in ["country", "region", "city", "org"]:
        if data.get(key):
            info += data[key] + ","
        else:
            """Если инфы нет, то напишем пользователю об этом"""
            info += '{} information is not available,'.format(key.upper())
    info = info[:-1]
    return info


def get_trace(dest_ip, ttl):
    """Создаем сокет
    AF - семейство адресов по IPv4
    тип сокета обычно либо SOCK_STREAM (для TCP), либо SOCK_DGRAM (для UDP)
    указываем "сырой" сокет (будет работать по указанному протоколу)
    socket.IPPROTO_ICMP - вот здесь и указываем, по какому протоколу сокету работать"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    """Устанавливаем тайм-аут в 2 секунды, чтобы все не повисло"""
    sock.settimeout(2)
    """Далее переназначаем TTL, который отправится в пакете с этого сокета
    SOL_IP (socket level) - IP
    IP-TTl - в заголовке IP переопределить значение TTL"""
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    """icmp-пакет (эхо-запрос) пакет с id=42 и sq_num=1"""
    icmp_echo_query = b'\x08\x00\xb5\xbc\x42\x42\x00\x01'
    try:
        """Отправляем запрос на 43 порт, получаем в ответе ip, 
        если ответ не успеет прийти, то скажем, что время ожидания вышло"""
        sock.sendto(icmp_echo_query, (dest_ip, 43))
        ip = sock.recvfrom(1024)[1]
        addr = ip[0]
        return addr
    except socket.timeout:
        return '*'
    finally:
        """Не забываем закрыть соединение"""
        sock.close()


def ip_is_white(ip):
    """Проверяем, не является ли полученный ip серым
    (питон сравнивает строки лексикографически)"""
    local_ip_addresses_diapasons = (
        ('10.0.0.0', '10.255.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'))

    for diapason in local_ip_addresses_diapasons:
        if diapason[0] <= ip <= diapason[1]:
            return False
    return True


if __name__ == '__main__':
    """Создаем парсер аргументов командной строки"""
    parser = argparse.ArgumentParser(description='Tracing AS by Rybakov Daniil', epilog='Ekaterinburg, 2018')
    """Добавляем в него аргумент для запроса"""
    parser.add_argument("destination", action='store', help="Destination address", type=str)
    args = parser.parse_args()  # Парсим аргументы
    destination_ip = socket.gethostbyname(args.destination)
    print("Destination is {} (ip - {})".format(args.destination, destination_ip))  # Получаем ip по доменному имени,
    # используя стандартные средства питона
    trace_as(destination_ip)  # Отправляем этот ip в функцию для трассировки

