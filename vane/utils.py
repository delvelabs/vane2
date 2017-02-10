import json


def load_model_from_file(filename, schema):
    with open(filename, "rt") as fp:
        model, errors = schema.load(json.load(fp))
        return model, errors
