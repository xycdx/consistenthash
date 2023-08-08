import base64
import hmac
import urllib.parse
import sys
import hashlib
import os

def get_authorization(url, app_id, app_salt):
    try:
        internal_url = urllib.parse.urlparse(url)
        singing_str = (
            internal_url.path + "\n" if not internal_url.query else internal_url.path + "?" + internal_url.query + "\n"
        )
        print(singing_str)
        encoded_sign = base64.urlsafe_b64encode(
            hmac.new(app_salt.encode(), singing_str.encode(), digestmod=hashlib.sha1).digest()
        ).decode()
        print(app_salt.encode())
        return encoded_sign
    except Exception as e:
        print(e)
        return None

if __name__ == "__main__":
    # 获取命令行参数
    if len(sys.argv) == 4:
        url = sys.argv[1]
        app_id = sys.argv[2]
        app_salt = sys.argv[3]
    else:
        url = 'https://api.qiniudns.com/v1/resolve?name=aqiniushare.tangdou.com'
        app_id = '44zpao7x7vyw9ncu'
        app_salt = '916c9boaawdlnxlle6k7472asee6h7y8'

    # 调用函数并打印返回值
    
    token = "Authorization: QApp 44zpao7x7vyw9ncu:" + get_authorization(url, app_id, app_salt)
    cmd  = 'curl -v -H "' + token + '" --alt-svc altsvc.cache --insecure --http3 ' + url
    os.system(cmd)