from os import path


class Database:

    def __init__(self, loop=None):
        self.loop = loop
        self.files_to_check = []
        self.api_url = None

    def load_data(self):
        missing_file = False
        if path.isdir("data"):
            for file in self.files_to_check:
                if not path.isfile("{0}/{1}".format("data", file)):
                    missing_file = True
                    break
            if missing_file:
                self.loop.run_until_complete(self.download_data_latest_release())
        else:
            self.loop.run_until_complete(self.download_data_latest_release())

    async def download_data_latest_release(self):
        latest_release = await self.get_latest_release()
        async with self.aiohttp_session.get(latest_release['assets_url']) as response:
            pass

    async def get_latest_release(self):
        pass
