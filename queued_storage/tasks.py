from django.core.cache import cache
from django.core.files.storage import get_storage_class
from django.conf import settings

from celery.registry import tasks
from celery.task import Task


from ncrypt.cipher import EncryptCipher, DecryptCipher
from ncrypt.rsa import RSAKey

def encrypt_file(rsa_key, in_file, out_file):
    while 1 :
        data = in_file.read(8192)
        if not data: break
        out_data = rsa_key.encrypt(data)
        out_file.write(out_data)

            
class SaveToRemoteTask(Task):
    def run(self, name, local, remote, cache_key):
        local_storage = get_storage_class(local)()
        remote_storage = get_storage_class(remote)()
        #encrypt
        if settings.ENCRYPT_UPLOADED_FILES:
            key = RSAKey()
            # Read in a public key
            fd = open(settings.CRYPTO_KEYS_PUBLIC, "rb")
            public_key = fd.read()
            fd.close()
            # import this public key
            key.fromPEM_PublicKey(public_key)            
            encrypt_file(key, local_storage.open(name),\
                local_storage.open(name, 'w'))
            remote_storage.save(name, local_storage.open(name))
        else:
            remote_storage.save(name, local_storage.open(name))
        cache.set(cache_key, True)
        return True
        
tasks.register(SaveToRemoteTask)
