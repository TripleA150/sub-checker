import base64
import json
import socket
import unittest

from checker import endpoint, extract, parse, reachable

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
            f"trojan://pass@h.example:443?security=tls&sni=h.example",
            vmess(tls="tls", scy="auto"),
            vmess(tls="none", scy="aes-128-gcm"),
        ]:
            self.assertIsNotNone(parse(link), link)

    def test_rejected(self):
        for link in [
            f"vless://{UUID}@h.example:443?encryption=none&type=tcp",
            # no security at all
            f"vless://{UUID}@h.example:443?encryption=mlkem768x25519plus.native.0rtt.key",
            f"vless://{UUID}@h.example:443?pbk=key&sni=h.example&type=tcp",
            "trojan://pass@h.example:443?sni=h.example",
            vmess(scy="aes-128-gcm"),
            vmess(tls="", scy="aes-128-gcm"),
            f"vless://{UUID}@h.example:443?security=none&encryption=none",
            f"vless://{UUID}@h.example:443?security=xtls",
            f"trojan://pass@h.example:443?security=none",
            vmess(tls=""),  # no explicit scy
            vmess(tls="none", scy="none"),
            vmess(tls="", scy="zero"),
            "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@1.2.3.4:8388",  # ss has no security field
            "vless://garbage",
        ]:
            self.assertIsNone(parse(link), link)

    def test_outbound_shape(self):
        ob = parse(f"vless://{UUID}@h.example:443?security=reality&pbk=key&sid=ab&sni=s.example"
                   f"&type=grpc&serviceName=svc&flow=xtls-rprx-vision")
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(ob["streamSettings"]["realitySettings"]["serverName"], "s.example")
        self.assertEqual(ob["streamSettings"]["grpcSettings"], {"serviceName": "svc", "multiMode": False})


class TestReachable(unittest.TestCase):
    def test_tcp(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen()
            self.assertTrue(reachable("127.0.0.1", srv.getsockname()[1], 1))

    def test_unresolvable(self):
        self.assertFalse(reachable("nonexistent.invalid", 443, 1))

    def test_endpoint(self):
        self.assertEqual(endpoint(parse("trojan://p@h.example:8443?security=tls")), ("h.example", 8443))
        self.assertEqual(endpoint(parse(vmess(tls="tls"))), ("1.2.3.4", 443))


class TestExtract(unittest.TestCase):
    def test_plain_and_base64(self):
        body = f"# comment\nvless://{UUID}@h:443?security=tls#a b\n\ntrojan://p@h:443\n"
        self.assertEqual(extract(body), [f"vless://{UUID}@h:443?security=tls#a b", "trojan://p@h:443"])
        self.assertEqual(extract(base64.b64encode(body.encode()).decode()), extract(body))
        self.assertEqual(extract("<html>not a subscription</html>"), [])


if __name__ == "__main__":
    unittest.main()
