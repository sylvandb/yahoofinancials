# decrypt encrypted responses ca 20221221
# from https://github.com/ranaroussi/yfinance/issues/1246#issuecomment-1356709536
#
# handle hidden encryption key 20230116, 20230123, 20230126
# from https://github.com/JECSand/yahoofinancials

from json import loads
from random import randrange
import re
import sys
import time

from base64 import b64decode
import hashlib
try:
    _UsingCryptodome = True
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    try:
        # Cryptodome installed by another name
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        _UsingCryptodome = False
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from .exceptions import DecryptException
    from .fetchurl import _fetch_url, _debug
except ImportError:
    from exceptions import DecryptException
    from fetchurl import _fetch_url, _debug



def decrypt(data, *pw_args):
    if data[:3] != 'U2F':
        return data
    password = _find_enckey(*pw_args)
    encrypted = b64decode(data)
    assert encrypted[:8] == b"Salted__"
    salt = encrypted[8:16]
    key, iv = _EVPKDF(password, salt, keySize=32, ivSize=16, iterations=1, hashAlgorithm="md5")
    return loads(_decrypt(encrypted[16:], key, iv))



if _UsingCryptodome:
    def _decrypt(ciphertext, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, IV=iv)
        plaintext = cipher.decrypt(ciphertext)
        return unpad(plaintext, 16, style="pkcs7")
else:
    def _decrypt(ciphertext, key, iv):
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(plaintext) + unpadder.finalize()).decode("utf-8")


def _find_enckey(data_obj, soup):
    # data_obj is the object from the original file
    # soup is the original file as a beautiful soup object

    # original obfuscated enc key
    try:
        _cs = data_obj["_cs"]
        _crdata = loads(data_obj["_cr"])
    except KeyError:
        pass
    else:
        _crwords = _crdata["words"]
        _cr = b"".join(int.to_bytes(i, length=4, byteorder="big", signed=True) for i in _crwords)
        assert _crdata["sigBytes"] == len(_cr)
        return hashlib.pbkdf2_hmac("sha1", _cs.encode("utf8"), _cr, 1, dklen=32).hex()

    # enc key in a single unexpected key
    #print('all %d keys: %r' % (len(data_obj), data_obj.keys(),))
    # over 10,000 random-looking keys with data! yahoo why you waste my bandwidth???
    parts = []
    for v in (v for k, v in data_obj.items() if k not in ('context', 'plugins',)):
        if parts:
            break
        parts.append(v)
    else:
        if len(parts) == 1 and all(parts):
            return ''.join(parts)

    # enc key as data in the only 4 keys after 'plugins'
    try:
        del data_obj['context']
    except KeyError:
        pass
    keys = list(data_obj.keys())
    try:
        plugins = keys.index('plugins')
    except ValueError:
        pass
    else:
        # limit to max 5 for efficiency and error checking
        keys = keys[plugins + 1 : plugins + 6]
        #print('keys: %r' % (keys,))
        parts = [data_obj.get(k) for k in keys]
        if len(parts) == 4 and all(parts):
            return ''.join(parts)

    # find and download main.js and look for 4 keys holding the enc key
    prefix = "https://s.yimg.com/uc/finance/dd-site/js/main."
    for url in (tag['src'] for tag in soup.find_all('script') if tag.get('src', '').startswith(prefix)):
        if _debug(): print('main url:', url, file=sys.stderr)
        status_code, content = _fetch_url(url)
        if status_code == 200:
            mainjs = content
            for dpstore in (x.group() for x in re.finditer(_dpregex, mainjs)):
                sublist = [x.group() for x in re.finditer(_slregex, dpstore)][:5]
                keys = [_clean_sl(sl) for sl in sublist]
                if _debug():
                    print(f'look dp: {dpstore}', file=sys.stderr)
                    print(f'look sl: {sublist}', file=sys.stderr)
                    print(f'look ky: {keys}', file=sys.stderr)
                parts = [data_obj.get(k) for k in keys]
                if len(parts) == 4 and all(parts):
                    if _debug(): print('unverified 4 from main.js', file=sys.stderr)
                    return ''.join(parts)
            time.sleep(randrange(10, 20))

    raise DecryptException('No enc key')


_dpregex = r"context.dispatcher.stores=JSON.parse((?:.*?\r?\n?)*)toString"
#_slregex = r"t\[\"((?:.*?\r?\n?)*)\"\]"
# ???
# "".concat(t.da2b70b6c4d3).concat(t.c6c907cd4e87).concat(t["52b5483ebbfb"]).concat(t.c8fe41bc5e8e)).toString
_slregex = r"concat\(t[\.\[]\"?((?:.*?\r?\n?)*)[a-f0-9]+\"?\]?\)"

def _clean_sl(s):
    # clean up the components matched by _slregex
    # seems like should be possible to integrate this into _slregex
    return s \
        .replace('concat(', '').replace(')', '') \
        .replace('t.', '') \
        .replace('t["', '').replace('"]', '')



def _EVPKDF(
    password,
    salt,
    keySize=32,
    ivSize=16,
    iterations=1,
    hashAlgorithm="md5",
) -> tuple:
    """OpenSSL EVP Key Derivation Function
    Args:
        password (Union[str, bytes, bytearray]): Password to generate key from.
        salt (Union[bytes, bytearray]): Salt to use.
        keySize (int, optional): Output key length in bytes. Defaults to 32.
        ivSize (int, optional): Output Initialization Vector (IV) length in bytes. Defaults to 16.
        iterations (int, optional): Number of iterations to perform. Defaults to 1.
        hashAlgorithm (str, optional): Hash algorithm to use for the KDF. Defaults to 'md5'.
    Returns:
        key, iv: Derived key and Initialization Vector (IV) bytes.
    Taken from: https://gist.github.com/rafiibrahim8/0cd0f8c46896cafef6486cb1a50a16d3
    OpenSSL original code: https://github.com/openssl/openssl/blob/master/crypto/evp/evp_key.c#L78
    """
    assert iterations > 0, "Iterations can not be less than 1."
    if isinstance(password, str):
        password = password.encode("utf-8")
    final_length = keySize + ivSize
    key_iv = b""
    block = None
    while len(key_iv) < final_length:
        hasher = hashlib.new(hashAlgorithm)
        if block:
            hasher.update(block)
        hasher.update(password)
        hasher.update(salt)
        block = hasher.digest()
        for _ in range(1, iterations):
            block = hashlib.new(hashAlgorithm, block).digest()
        key_iv += block
    key, iv = key_iv[:keySize], key_iv[keySize:final_length]
    return key, iv




if __name__ == '__main__':

    from bs4 import BeautifulSoup

    try:
        ticker = sys.argv[1]
    except IndexError:
        #ticker = 'lmt'
        ticker = 'mmm'

    with open(f'{ticker}.html', 'r') as f:
        page = f.read()

    with open(f'{ticker}-main.js', 'r') as f:
        mainjs = f.read()
        #mainjs = content


    def _fetch_url(u):
        print(f'url: {u}')
        return 200, mainjs


    soup = BeautifulSoup(page, "html.parser")
    re_script = soup.find("script", text=re.compile("root.App.main"))
    script = re_script.text or re_script.string
    data_obj = loads(re.search("root.App.main\s+=\s+(\{.*\})", script).group(1))
    datastore = data_obj["context"]["dispatcher"]["stores"]
    store = decrypt(datastore, data_obj, soup)
    print(f"decrypted {len(datastore)} bytes to {len(store)} {type(store)} ({len(str(store))} as str).")

