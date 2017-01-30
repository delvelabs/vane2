from openwebvulndb.common.hash import hash_data


class HashResponse:

    async def after_response(self, entry):
        if not entry.response.truncated:
            try:
                hash_algo = entry.arguments['hash_algo']
                entry.result.hash = hash_data(entry.response.raw, hash_algo)
            except KeyError:
                return
