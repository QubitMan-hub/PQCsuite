import hashlib
import os


def digest(data, name):
    return hashlib.new(name, data).hexdigest()


def handler(request):
    return digest(request.body, request.headers.get("X-Digest", os.environ.get("DIGEST_NAME")))
