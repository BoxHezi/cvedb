# import zlib
import pickle

import pgzip


def compress(data: bytes):
    # return zlib.compress(data)
    return pgzip.compress(data)


def decompress(data: bytes):
    # return zlib.decompress(data)
    return pgzip.decompress(data)


def serialize(obj: object):
    return pickle.dumps(obj)


def deserialize(data: bytes):
    return pickle.loads(data)


def pickle_dump(path, obj):
    with open(path, "wb") as file:
        pickle.dump(obj, file)


def pickle_load(path):
    with open(path, "rb") as file:
        return pickle.load(file)