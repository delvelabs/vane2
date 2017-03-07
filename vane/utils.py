import json
from urllib.parse import urlparse
import re


def load_model_from_file(filename, schema):
    with open(filename, "rt") as fp:
        model, errors = schema.load(json.load(fp))
        return model, errors


def validate_url(url):
    result = urlparse(url)
    if len(result.scheme) == 0 or len(result.netloc) == 0:
        return False
    if not re.match("https?", result.scheme):
        return False
    return True


def normalize_url(url):
    if not url.endswith("/"):
        url += "/"
    return url
