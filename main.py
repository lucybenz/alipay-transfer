import random

import requests

from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from urllib.parse import quote_plus

from base64 import decodebytes, encodebytes

import json


class AliPay(object):
    """
    支付宝支付接口
    """

    def __init__(self, app_private_key_path, alipay_public_key_path):
        self.appid = '2016101100661300'
        self.gateway = "https://openapi.alipaydev.com/gateway.do"
        self.app_private_key_path = app_private_key_path
        self.app_private_key = None

        with open(self.app_private_key_path) as fp:
            self.app_private_key = RSA.importKey(fp.read())

        self.alipay_public_key_path = alipay_public_key_path
        with open(self.alipay_public_key_path) as fp:
            self.alipay_public_key = RSA.import_key(fp.read())

    def direct_pay(self, out_trade_no, total_amount):
        biz_content = {
            "out_biz_no": out_trade_no,
            "trans_amount": total_amount,
            "product_code": "TRANS_ACCOUNT_NO_PWD",
            'order_title': '沙箱环境转账测试',
            'biz_scene': 'DIRECT_TRANSFER',
            'payee_info': {
                'identity': 'ifbwfj2078@sandbox.com',
                'identity_type': 'ALIPAY_LOGON_ID',
                'name': '沙箱环境'
            }
        }

        data = self.build_body("alipay.fund.trans.uni.transfer", biz_content)
        return self.sign_data(data)

    def build_body(self, method, biz_content):
        data = {
            "app_id": self.appid,
            "method": method,
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }
        return data

    def sign_data(self, data):
        data.pop("sign", None)
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in unsigned_items)
        sign = self.sign(unsigned_string.encode("utf-8"))
        # ordered_items = self.ordered_data(data)
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in unsigned_items)
        # 获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    def ordered_data(self, data):
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))

        return sorted([(k, v) for k, v in data.items()])

    def sign(self, unsigned_string):
        # 开始计算签名
        key = self.app_private_key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))
        # base64 编码，转换为unicode表示并移除回车
        sign = encodebytes(signature).decode("utf8").replace("\n", "")
        return sign

    def _verify(self, raw_content, signature):
        # 开始计算签名
        key = self.alipay_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        if signer.verify(digest, decodebytes(signature.encode("utf8"))):
            return True
        return False

    def verify(self, data, signature):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        message = "&".join(u"{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(message, signature)


if __name__ == "__main__":
    alipay = AliPay(
        app_private_key_path='private_key.txt',
        alipay_public_key_path='pub_key.txt'
    )

    url = alipay.direct_pay(
        out_trade_no="20000513" + str(random.randint(1000, 9999)),
        total_amount='100.00',
    )
    res = requests.get(url=alipay.gateway, params=url)
    print(res.json())
