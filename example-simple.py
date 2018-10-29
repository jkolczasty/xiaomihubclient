#!/usr/bin/python3

import logging
from xiaomihubclient import XiaomiHubClient
import time

logging.basicConfig(level=logging.INFO)
_LOGGER = logging.getLogger(__name__)


if __name__ == "__main__":
    #logging.getLogger().setLevel(logging.DEBUG)
    gateway_secret_key = "xxxxxxxxxxxxxxxxxxxx"
    polling_interval = 2
    gateway_ip = "192.168.4.209"

    gateway = XiaomiHubClient(gateway_secret_key, gateway_ip, unwanted_data_fix=True)
    gateway.open()
    gateway.discovery()

    last_poll = 0

    try:
        while True:
            ct = time.time()
            if abs(ct - last_poll) < 2:
                time.sleep(1)
                continue

            last_poll = ct
            data = gateway.poll()
            if not data:
                continue

            for d in data:
                print("READ: {0} ({1}): {2} = {3}".format(d['model'], d['type'], d['sid'], d['data']))
    except KeyboardInterrupt:
        gateway.close()
