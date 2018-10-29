#!/usr/bin/python3

import logging
from xiaomihubclient import XiaomiHubClientThread
import time

logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)


def poll_callback(data):
    for d in data:
        print("READ: {0} ({1}): {2} = {3}".format(d['model'], d['type'], d['sid'], d['data']))


if __name__ == "__main__":
    #logging.getLogger().setLevel(logging.DEBUG)
    gateway_secret_key = "xxxxxxxxxxxxxxxxxxxx"
    polling_interval = 2
    gateway_ip = "192.168.4.209"

    gateway = XiaomiHubClientThread(poll_callback, gateway_secret_key, gateway_ip, unwanted_data_fix=True)
    gateway.open()
    gateway.discovery()

    last_poll = 0

    try:
        gateway.start()

        while gateway.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        gateway.stop()
        gateway.close()
