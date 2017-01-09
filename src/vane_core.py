from hammertime import HammerTime
from hammertime.rules import IgnoreLargeBody

import logging

from os.path import join, dirname


class Vane:

    def __init__(self):
        self.hammertime = HammerTime(retry_count=3)
        self.config_hammertime()

    def config_hammertime(self):
        self.hammertime.heuristics.add_multiple([IgnoreLargeBody()])
        logging.basicConfig(filename=join(dirname(__file__), "general_log"), level=logging.DEBUG)

    async def do_request(self, url):
        logging.info("sending request to %s" % url)
        self.hammertime.request(url)

        success = False
        async for entry in self.hammertime.successful_requests():
            success = True

        if success:
            logging.info("request successful")
            print("Request to {0} successful.".format(url))
        else:
            print("Request to {0} not successful.".format(url))
            logging.info("request failed")

        await self.hammertime.close()

    # TODO
    async def import_openwebvulndatabase(self, database_path, export_path):
        """Import data from openwebvulndb and repackage it in a more compact database."""
        pass

    def perfom_action(self, action="request", url=None, database_path=None):
        if action == "request":
            if url is None:
                raise ValueError("Target url required.")
            self.hammertime.loop.run_until_complete(self.do_request(url))
        elif action == "import_data":
            pass
