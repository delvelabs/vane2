from hammertime.ruleset import StopRequest


class RetryOnErrors:

    def __init__(self, errors):
        self.errors_set = errors

    async def after_headers(self, entry):
        if entry.response.code in self.errors_set:
            raise StopRequest("Status code %s, retry request" % entry.response.code)
