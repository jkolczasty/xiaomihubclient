#
# (c) jkolczasty@gmail.com
#
# Based on https://github.com/monster1025/aqara-mqtt by Monster1025
#
#


import socket
import struct
import json
import logging
import time
from threading import Thread

_LOGGER = logging.getLogger("xiaomihubclient")

XIAOMI_HUB_DEVICE_TYPES = {
    'hub': 'hub',
    'sensor_ht': 'sensor',
    'weather.v1': 'sensor',
    'sensor_wleak.aq1': 'sensor',
    'magnet': 'binary_sensor',
    'sensor_magnet.aq2': 'binary_sensor',
    'motion': 'binary_sensor',
    'sensor_motion.aq2': 'binary_sensor',
    'switch': 'binary_sensor',
    'sensor_switch.aq2': 'binary_sensor',
    '86sw1': 'binary_sensor',
    '86sw2': 'binary_sensor',
    'cube': 'binary_sensor',
    'plug': 'switch',
    'ctrl_neutral1': 'switch',
    'ctrl_neutral2': 'switch'
}


class XiaomiHubClient:
    GATEWAY_KEY = None
    GATEWAY_IP = None
    GATEWAY_PORT = None
    GATEWAY_SID = None
    GATEWAY_TOKEN = None

    XIAOMI_DEVICES = None

    MULTICAST_ADDRESS = '224.0.0.50'
    MULTICAST_PORT = 9898
    GATEWAY_DISCOVERY_ADDRESS = '224.0.0.50'
    GATEWAY_DISCOVERY_PORT = 4321
    SOCKET_BUFSIZE = 1024

    def __init__(self, key, gateway_ip=None, **config):
        self.GATEWAY_KEY = key
        self.XIAOMI_DEVICES = dict()
        self._queue = None
        self._socket = None
        self._mcastsocket = None
        self._read_unwanted_data_enabled = True

        if gateway_ip is not None:
            self.GATEWAY_DISCOVERY_ADDRESS = gateway_ip

        unwanted_data_fix = config.get('unwanted_data_fix')
        if unwanted_data_fix is not None:
            self._read_unwanted_data_enabled = unwanted_data_fix is True
            _LOGGER.info('"Read unwanted data" fix is {0}'.format(self._read_unwanted_data_enabled))

    def discovery(self):
        try:
            _LOGGER.info('Discovering Xiaomi Gateways using address {0}'.format(self.GATEWAY_DISCOVERY_ADDRESS))
            data = self._send_socket('{"cmd":"whois"}', "iam", self.GATEWAY_DISCOVERY_ADDRESS,
                                     self.GATEWAY_DISCOVERY_PORT)
            if data["model"] == "gateway":
                self.GATEWAY_IP = data["ip"]
                self.GATEWAY_PORT = int(data["port"])
                self.GATEWAY_SID = data["sid"]
                _LOGGER.info('Gateway found on IP {0}'.format(self.GATEWAY_IP))
                self._discover_devices()
                return True
            else:
                _LOGGER.error('Error with gateway response : {0}'.format(data))
        except Exception as e:
            _LOGGER.error("Cannot discover hub using whois: {0}".format(e))
            return False

        if self.GATEWAY_IP is None:
            _LOGGER.error('No Gateway found. Cannot continue')
            return False

    def open(self):
        _LOGGER.info('Open socket')
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.settimeout(1)

        self._mcastsocket = self._create_mcast_socket()

    def close(self):
        _LOGGER.info('Close socket')
        if self._socket:
            self._socket.close()
            self._socket = None
        if self._mcastsocket:
            self._mcastsocket.close()
            self._mcastsocket = None

    def _discover_devices(self):
        _LOGGER.info('Discovering Xiaomi Devices')
        cmd = '{"cmd" : "get_id_list"}'
        resp = self._send_cmd(cmd, "get_id_list_ack")
        self.GATEWAY_TOKEN = resp["token"]
        sids = json.loads(resp["data"])

        self.XIAOMI_DEVICES = dict()

        xiaomi_device = dict(model='hub', type='hub', sid=self.GATEWAY_SID, short_id=self.GATEWAY_SID, data={})
        self.XIAOMI_DEVICES[self.GATEWAY_SID] = xiaomi_device

        for sid in sids:
            cmd = '{"cmd":"read","sid":"' + sid + '"}'
            resp = self._send_cmd(cmd, "read_ack")
            model = resp["model"]

            sid = resp["sid"]
            device_type = XIAOMI_HUB_DEVICE_TYPES.get(model) or 'sensor'
            xiaomi_device = dict(model=model, type=device_type, sid=sid, short_id=resp["short_id"],
                                 data=json.loads(resp["data"]))

            self.XIAOMI_DEVICES[sid] = xiaomi_device

        _LOGGER.info('Found {0} devices'.format(len(self.XIAOMI_DEVICES)))

    def _send_cmd(self, cmd, rtnCmd):
        return self._send_socket(cmd, rtnCmd, self.GATEWAY_IP, self.GATEWAY_PORT)

    def _read_unwanted_data(self):
        if not self._read_unwanted_data_enabled:
            return

        try:
            _socket = self._socket
            _socket.settimeout(1)
            data = _socket.recv(4096)
            _LOGGER.error("Unwanted data recieved: %s", str(data))
        except socket.timeout:
            pass
        except Exception as e:
            _LOGGER.error("Cannot read unwanted data: %s", str(e))

    def _send_socket(self, cmd, rtnCmd, ip, port):
        _socket = self._socket
        try:
            _LOGGER.debug('Sending to GW {0}'.format(cmd))
            self._read_unwanted_data()
            _socket.settimeout(5)
            _socket.sendto(cmd.encode(), (ip, port))
            _socket.settimeout(5)
            try:
                data, addr = _socket.recvfrom(1024)
            except socket.timeout:
                _LOGGER.warning("Socket read timeout for: %s", cmd)
                return None

            if data is not None:
                resp = json.loads(data.decode())
                _LOGGER.debug('Recieved from GW {0}'.format(resp))
                if resp["cmd"] == rtnCmd:
                    return resp
                else:
                    _LOGGER.error("Response from {0} does not match return cmd".format(ip))
                    _LOGGER.error(data)
            else:
                _LOGGER.error("No response from Gateway")
        except socket.timeout:
            _LOGGER.error("Cannot connect to Gateway")
            # TODO: reconnect?

    # def write_to_hub(self, sid, **values):
    #     key = self._get_key()
    #     cmd = {
    #         "cmd": "write",
    #         "sid": sid,
    #         "data": dict(key=key, **values)
    #     }
    #     return self._send_cmd(json.dumps(cmd), "write_ack")

    def get_from_hub(self, sid):
        cmd = '{ "cmd":"read","sid":"' + sid + '"}'
        return self._send_cmd(cmd, "read_ack")

    # def _get_key(self):
    #     from Crypto.Cipher import AES
    #     IV = bytes(bytearray.fromhex('17996d093d28ddb3ba695a2e6f58562e'))
    #     encryptor = AES.new(self.GATEWAY_KEY, AES.MODE_CBC, IV=IV)
    #     ciphertext = encryptor.encrypt(self.GATEWAY_TOKEN)
    #     return ''.join('{:02x}'.format(x) for x in ciphertext)

    def _create_mcast_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.MULTICAST_ADDRESS, self.MULTICAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(self.MULTICAST_ADDRESS), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)
        return sock

    def poll(self):
        data = []
        for sid, device in self.XIAOMI_DEVICES.items():
            sensor_resp = self.get_from_hub(sid)
            if sensor_resp is None:
                _LOGGER.warning("Failed to read: %s", sid)
                continue

            try:
                sensor_resp['type'] = device.get('type')
                sensor_resp['data'] = json.loads(sensor_resp['data'])
                data.append(sensor_resp)
            except Exception as e:
                _LOGGER.error("Exception: %s: %s", e.__class__.__name__, e)

        return data


class XiaomiHubClientThread(XiaomiHubClient, Thread):
    running = None

    def __init__(self, poll_callback, key, gateway_ip=None, **config):
        self.poll_callback = poll_callback
        self.poll_interval = config.get('poll_interval') or 10
        self.last_poll = 0
        super(XiaomiHubClientThread, self).__init__(key, gateway_ip, **config)
        Thread.__init__(self)

    def start(self):
        self.running = True
        return super(XiaomiHubClientThread, self).start()

    def stop(self):
        _LOGGER.info("Stopping")
        self.running = False
        self.join()

    def _run(self):
        while self.running:
            ct = time.time()
            if abs(ct - self.last_poll) >= self.poll_interval:
                self.last_poll = ct
                try:
                    data = self.poll()
                    if data:
                        self.poll_callback(data)
                except Exception as e:
                    _LOGGER.exception("Exception")

            if self._mcastsocket is not None:
                try:
                    data, addr = self._mcastsocket.recvfrom(self.SOCKET_BUFSIZE)
                except socket.timeout:
                    continue

                try:
                    data = json.loads(data.decode("ascii"))
                    cmd = data['cmd']
                    _LOGGER.debug(format(data))
                    if cmd == 'heartbeat' and data['model'] == 'gateway':
                        self.GATEWAY_TOKEN = data['token']
                    elif cmd == 'report' or cmd == 'heartbeat':
                        pass
                    else:
                        _LOGGER.error('Unknown multicast data : {0}'.format(data))
                except Exception as e:
                    _LOGGER.error('Cannot process multicast message : {0}'.format(data))
                    raise

    def run(self):
        try:
            self._run()
        except Exception as e:
            _LOGGER.error("Exception: %s: %s", e.__class__.__name__)

        _LOGGER.info("Thread exit")
