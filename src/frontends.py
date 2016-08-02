"""

This module helps handling tBB front-ends.

"""


import asyncio
import json
import logging
import datetime
from aiohttp import web
from asyncio import coroutine
from net_elements import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class FrontendsHandler(object):
    def __init__(self, tracker, password, host='192.168.2.90', port=1984, loop=None):
        self.tracker = tracker
        self.password = password
        self.port = port
        self.host = host
        self.app = web.Application(logger=logger)
        # self.sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        # self.sslcontext.verify_mode = ssl.CERT_REQUIRED
        # self.sslcontext.check_hostname = True
        # self.sslcontext.load_verify_locations(os.path.join(os.getcwd(), "certs", "server.pem"))
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

    @coroutine
    def start(self):
        self.loop = asyncio.get_event_loop()
        self.handler = self.app.make_handler(logger=logger)
        while True:
            try:
                if hasattr(self, 'sslcontext'):
                    sslcon = self.sslcontext
                else:
                    sslcon = None
                self.srv = yield from self.loop.create_server(
                    self.handler, self.host, self.port, ssl=sslcon
                )
                break
            except OSError:
                self.port += 1
            if self.port >= 1984+20:
                raise Exception("Couldn't find a port for opening socket.")
        self.bind()
        logger.info("Frontend socket opened at {}://{}:{}/.".format(
            'https' if sslcon else 'http',
            self.host, self.port
        ))

    def close(self):
        self.srv.close()
        self.loop.run_until_complete(self.srv.wait_closed())
        self.loop.run_until_complete(self.app.shutdown())
        self.loop.run_until_complete(self.handler.finish_connections(1.0))
        self.loop.run_until_complete(self.app.cleanup())

    def bind(self):
        self.app.router.add_route('GET', '/test/', self.test)
        self.app.router.add_route('GET', '/stats/{password}/', self.stats)
        self.app.router.add_route('GET', '/ip_info/{addr}/{password}/', self.ip_info)
        self.app.router.add_route('GET', '/mac_info/{addr}/{password}/', self.mac_info)
        self.app.router.add_route('GET', '/status/{password}/', self.status)
        self.app.router.add_route('GET', '/settings/get/{what}/{password}/', self.settings_get)
        self.app.router.add_route('GET', '/settings/set/{what}/{value}/{password}/', self.settings_set)
        self.app.router.add_route('GET', '/ignore/{method}/{ip}/{password}/', self.ignore)
        self.app.router.add_route('GET', '/is_ignored/{ip}/{password}/', self.is_ignored)
        self.app.router.add_route('GET', '/is_mac_ignored/{mac}/{password}/', self.is_mac_ignored)
        self.app.router.add_route('GET', '/set_priority/{ip}/{value}/{password}/', self.set_priority)
        self.app.router.add_route('GET', '/ip_host_changes/{ip}/{from}/{to}/{password}/', self.ip_host_changes)
        self.app.router.add_route('GET', '/mac_host_changes/{mac}/{from}/{to}/{password}/', self.mac_host_changes)

    @coroutine
    def test(self, request):
        return web.Response(body=b"Connectivity test.")

    @coroutine
    def stats(self, request):
        self.check_request_input(request, [])
        hosts_up = []
        for host in self.tracker.ip_hosts:
            hosts_up.append((host.as_string(), self.tracker.ip_hosts[host].mac))
        return web.Response(body=json.dumps({
            'network': self.tracker.network.as_string(),
            'up_hosts': self.tracker.up_hosts,
            'hosts_up': hosts_up,
        }).encode('utf-8'))

    @coroutine
    def ip_info(self, request):
        check = self.check_request_input(request, ['addr'])
        if check is not None:
            return check
        as_ip = self.check_ip(request.match_info['addr'])
        if not isinstance(as_ip, IPElement):
            return as_ip
        host = self.tracker.ip_hosts[as_ip]
        info = {
            'ip': as_ip.as_string(),
            'is_up': host.is_up,
            'mac': host.mac,
            'method': host.last_discovery_method,
            'last_check': host.last_check.timestamp(),
            'last_seen': host.last_seen.timestamp(),
            'mac_history': {},
            'is_up_history': {},
            'discovery_history': {},
        }
        for history_name in ('mac', 'is_up', 'discovery'):
            history_name += "_history"
            history = getattr(host, history_name)
            for entry in history:
                encoded = entry.timestamp()
                info[history_name][encoded] = history[entry]
        return web.Response(
            body=json.dumps(info).encode('utf-8'))

    @coroutine
    def mac_info(self, request):
        check = self.check_request_input(request, ['addr'])
        if check is not None:
            return check
        as_mac = self.check_mac(request.match_info['addr'])
        if not isinstance(as_mac, MACElement):
            return as_mac
        if request.match_info['password'] != self.password:
            logger.error("somebody tried to access tBB with wrong password. Got: '{}' while password is '{}'".format(
                request.match_info['password'], self.password
            ))
            return web.Response(status=401, body=request.match_info['password'].decode('utf-8'))  # Unauthorized
        host = self.tracker.mac_hosts[as_mac]
        info = {
            'mac': as_mac.mac,
            'last_update': host.last_update.timestamp(),
            'last_seen': host.last_seen.timestamp(),
            'ip': host.ip[0].ip[0],
            'is_up': host.is_up,
            'history': {},
            'is_up_history': {},
        }
        for entry in host.is_up_history:
            encoded = str(entry.timestamp())
            info['is_up_history'][encoded] = host.is_up_history[entry]
        for entry in host.history:
            encoded = str(entry.timestamp())
            encoded_ips = []
            for ip in host.history[entry]:
                encoded_ips.append(ip.ip[0])
            info['history'][encoded] = encoded_ips
        return web.Response(
            body=json.dumps(info).encode('utf-8'))

    @coroutine
    def status(self, request):
        check = self.check_request_input(request, [])
        if check is not None:
            return check
        info = {}
        for i, track in enumerate(self.tracker.trackers):
            info.update({
               i: (track.outer_status, track.status)
            })
        return web.Response(
            body=json.dumps(info).encode('utf-8'))

    @coroutine
    def settings_get(self, request):
        check = self.check_request_input(request, ['what'])
        if check is not None:
            return check
        settings = {
            'time_between_checks': [t.total_seconds() for t in self.tracker.time_between_checks],
            'maximum_seconds_randomly_added': self.tracker.maximum_seconds_randomly_added,
            'auto_ignore_broadcasts': self.tracker.auto_ignore_broadcasts,
        }
        if request.match_info['what'] not in settings and request.match_info['what'] != 'all':
            return web.Response(status=406, body=b"what invalid.")  # NotAcceptable
        if request.match_info['what'] == 'all':
            return web.Response(
                body=json.dumps(settings).encode('utf-8'))
        return web.Response(
            body=json.dumps(settings[request.match_info['what']]).encode('utf-8')
        )

    @coroutine
    def settings_set(self, request):
        check = self.check_request_input(request, ['what','value'])
        if check is not None:
            return check
        what = request.match_info['what']
        value = request.match_info['value']
        if what == 'time_between_checks':
            try:
                _value = value.split(':')
                value = []
                for v in _value:
                    value.append(int(v))
            except:
                return web.Response(status=406, body=b"value invalid.")  # NotAcceptable
            if len(value) != 2:
                return web.Response(status=406, body=b"value invalid.")  # NotAcceptable
            self.tracker.time_between_checks = datetime.timedelta(minutes=value[0], seconds=value[1])
            return web.Response(status=200)
        elif what == 'maximum_seconds_randomly_added':
            try:
                value = int(value)
            except ValueError:
                return web.Response(status=406, body=b"value invalid.")  # NotAcceptable
            else:
                self.tracker.maximum_seconds_randomly_added = value
                return web.Response(status=200)
        elif what == 'auto_ignore_broadcasts':
            if value == 'True':
                self.tracker.auto_ignore_broadcasts = True
                return web.Response(status=200)
            elif value == 'False':
                self.tracker.auto_ignore_broadcasts = False
                return web.Response(status=200)
            else:
                return web.Response(status=406, body=b"value invalid.")  # NotAcceptable
        else:
            return web.Response(status=406, body=b"what invalid.")  # NotAcceptable

    @coroutine
    def ignore(self, request):
        check = self.check_request_input(request, ['method', 'ip'])
        if check is not None:
            return check
        as_ip = self.check_ip(request.match_info['ip'])
        if as_ip is not None:
            return as_ip
        method = request.match_info['method']
        if method == 'add':
            _ignore_list = self.tracker.ignore
            _ignore_list.append(as_ip)
            ignore_list = []
            for elem in _ignore_list:
                if elem not in ignore_list:
                    ignore_list.append(elem)
            self.tracker.ignore = ignore_list
            return web.Response(status=200)
        elif method == 'remove':
            ignore_list = []
            for elem in self.tracker.ignore:
                if elem != as_ip and elem not in ignore_list:
                    ignore_list.append(elem)
            self.tracker.ignore = ignore_list
            return web.Response(status=200)
        else:
            return web.Response(status=406, body=b"method invalid.")

    @coroutine
    def is_ignored(self, request):
        check = self.check_request_input(request, ['ip'])
        if check is not None:
            return check
        as_ip = self.check_ip(request.match_info['ip'])
        if isinstance(as_ip, web.Response):
            return as_ip
        is_ignored = {as_ip.ip[0]: as_ip in self.tracker.ignore}
        return web.Response(status=200, body=
            json.dumps(is_ignored).encode('utf-8')
        )

    @coroutine
    def is_mac_ignored(self, request):
        check = self.check_request_input(request, ['mac'])
        if check is not None:
            return check
        as_mac = self.check_mac(request.match_info['mac'], check_in_tracker=False)
        if isinstance(as_mac, web.Response):
            return as_mac
        is_ignored = {as_mac.mac: as_mac in self.tracker.ignore_mac}
        return web.Response(status=200, body=
            json.dumps(is_ignored).encode('utf-8')
        )

    @coroutine
    def set_priority(self, request):
        check = self.check_request_input(request, ['ip', 'value'])
        if check is not None:
            return check
        value = request.match_info['value']
        try:
            value = int(value)
        except ValueError:
            return web.Response(status=406, body=b"value is invalid.")
        self.tracker.priorities[as_ip] = value
        return web.Response(status=200)

    @coroutine
    def ip_host_changes(self, request):
        check = self.check_request_input(request, ['ip', 'from', 'to'])
        if check is not None:
            return check
        if request.match_info['ip'] == 'all':
            as_ip = None
        else:
            as_ip = self.check_ip(request.match_info['ip'])
            if not isinstance(as_ip, IPElement):
                return as_ip
        from_ = self.check_datetime(request.match_info['from'])
        if not isinstance(from_, datetime.datetime):
            return from_
        to = self.check_datetime(request.match_info['to'])
        if not isinstance(from_, datetime.datetime):
            return from_
        if as_ip is None:
            changes = yield from self.tracker.ip_changes([], from_, to, json_compatible=True)
        else:
            changes = yield from self.tracker.ip_changes([IPHost(as_ip)], from_, to, json_compatible=True)
        return web.Response(status=200, body=
            json.dumps(changes).encode('utf-8')
        )

    @coroutine
    def mac_host_changes(self, request):
        check = self.check_request_input(request, ['mac', 'from', 'to'])
        if check is not None:
            return check
        if request.match_info['mac'] == 'all':
            as_mac = None
        as_mac = self.check_mac(request.match_info['mac'])
        if not isinstance(as_mac, MACElement):
            return as_mac
        from_ = self.check_datetime(request.match_info['from'])
        to = self.check_datetime(request.match_info['to'])
        if as_mac is None:
            changes = yield from self.tracker.changes([], from_, to, json_compatible=True)  ### !!! also do this in self.ip_host_changes
        else:
            changes = yield from self.tracker.changes([MACHost(as_mac)], from_, to, json_compatible=True)
        return web.Response(status=200, body= \
            json.dumps(changes).encode('utf-8')
        )

    def check_request_input(self, input, expected, password=True):
        if password:
            expected.append('password')
        if len(input.match_info) != len(expected):
            return web.Response(status=404)  # NotFound  # aiohttp should do this on its own, but ok
        for exp in expected:
            if exp not in input.match_info:
                return web.Response(status=400, body="{} not set.".format(exp).encode('utf-8'))  # BadRequest
        if password:
            if input.match_info['password'] != self.password:
                logger.error("somebody tried to access tBB with wrong password. Got: '{}' while password is '{}'.".format(
                    input.match_info['password'], self.password
                ))
                return web.Response(status=401, body=input.match_info['password'].encode('utf-8'))  # Unauthorized

    def check_ip(self, ip, check_in_tracker=True):
        try:
            as_ip = IPElement(ip=ip, mask=self.tracker.network.mask)
        except:
            return web.Response(status=406, body=b"ip invalid.")  # NotAcceptable
        if as_ip not in self.tracker.ip_hosts and check_in_tracker:
            return web.Response(status=406, body=b"ip not found.")  # NotAcceptable
        return as_ip

    def check_mac(self, mac, check_in_tracker=True):
        try:
            as_mac = MACElement(mac)
        except:
            return web.Response(status=406, body=b"mac invalid.")  # NotAcceptable
        if as_mac not in self.tracker.mac_hosts and check_in_tracker:
            return web.Response(status=406, body=b"mac not found.")  # NotAcceptable
        return as_mac

    def check_datetime(self, input, accept_now=True):
        # expected format: dd.mm.yyyy-hh.mm.ss
        if accept_now:
            if input == 'now':
                return datetime.datetime.now()
        try:
            datet = []
            for got in input.split('-'):
                for g in got.split('.'):
                    datet.append(int(g))
            return datetime.datetime(
                day=datet[0], month=datet[1], year=datet[2], hour=datet[3], minute=datet[4], second=datet[5])
        except:
            return web.Response(status=406, body=b"date is invalid.")  # NotAcceptable
