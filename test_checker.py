import base64
import json
import unittest

from checker import extract, parse

UUID = "9a0e84f8-4b58-477f-99da-5fac5a2e58e8"


def vmess(**kw):
    j = {"v": "2", "add": "1.2.3.4", "port": "443", "id": UUID, "aid": "0", "net": "tcp", **kw}
    return "vmess://" + base64.b64encode(json.dumps(j).encode()).decode()


class TestFilter(unittest.TestCase):
    def test_accepted(self):
        for link in [
            f"vless://{UUID}@h.example:443?security=reality&pbk=key&sid=ab&sni=h.example&type=tcp#name",
            f"vless://{UUID}@h.example:443?security=tls&type=ws&path=%2Fws&host=h.example",
            f"vless://{UUID}@h.example:443?security=none&encryption=mlkem768x25519plus.native.0rtt.key",
            f"trojan://pass@h.example:443?sni=h.example",  # trojan defaults to tls
            vmess(tls="tls", scy="auto"),
            vmess(tls="", scy="aes-128-gcm"),
            "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:pw").decode() + "@1.2.3.4:8388#n",
            "ss://" + base64.b64encode(b"aes-256-gcm:pw@1.2.3.4:8388").decode(),
        ]:
            self.assertIsNotNone(parse(link), link)

    def test_rejected(self):
        for link in [
            f"vless://{UUID}@h.example:443?encryption=none&type=tcp",
            f"vless://{UUID}@h.example:443?security=none&encryption=none",
            f"vless://{UUID}@h.example:443?security=xtls",
            f"trojan://pass@h.example:443?security=none",
            vmess(tls=""),  # no explicit scy
            vmess(tls="none", scy="none"),
            vmess(tls="", scy="zero"),
            "ss://" + base64.b64encode(b"none:pw").decode() + "@1.2.3.4:8388",
            "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@1.2.3.4:8388?plugin=obfs-local",
            "vless://garbage",
        ]:
            self.assertIsNone(parse(link), link)

    def test_outbound_shape(self):
        ob = parse(f"vless://{UUID}@h.example:443?security=reality&pbk=key&sid=ab&sni=s.example"
                   f"&type=grpc&serviceName=svc&flow=xtls-rprx-vision")
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(ob["streamSettings"]["realitySettings"]["serverName"], "s.example")
        self.assertEqual(ob["streamSettings"]["grpcSettings"], {"serviceName": "svc", "multiMode": False})


class TestExtract(unittest.TestCase):
    def test_plain_and_base64(self):
        body = f"# comment\nvless://{UUID}@h:443?security=tls#a b\n\ntrojan://p@h:443\n"
        self.assertEqual(extract(body), [f"vless://{UUID}@h:443?security=tls#a b", "trojan://p@h:443"])
        self.assertEqual(extract(base64.b64encode(body.encode()).decode()), extract(body))
        self.assertEqual(extract("<html>not a subscription</html>"), [])


if __name__ == "__main__":
    unittest.main()
