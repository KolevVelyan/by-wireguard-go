For the setup you'll need two keypairs - one for the server (running userspace-wireguard) and one for the peer (running any wireguard distribution). You can get them using either `tetherctl`, any wireguard app or if you want here are some pairs:

| Rank |                  Private Key                 |                  Public Key                  |
|:----:|:--------------------------------------------:|:--------------------------------------------:|
|   1  | IPvZz9Re4O4tPkJusIv9YBnxmZ00tANOs3VyhbuVj1A= | 8LKqv9iHzy/VFnmkteRQpeM9M5wQfOJT3G3zi6MW5nU= |
|   2  | UM0HWVhHXBK1bei7bFUTL3hQdZN2a/reuGorE5nKfWw= | oVkEbv01jFkZ4UbPq+Q6BKI4GF0wxm/jpxs1PuD/F1k= |
|   3  | CPRNXIzpIpZQNcBOyYTAZTv37dOgVZJWpMIuSA2GNlk= | WfVqa1fH937+XFFmerVDapJSQgm9KN16bfmEIWDfo3M= |
|   4  | aHZBDKy7tUafzrhVqD5tDY3QdAQnBz9d3RTxq/sr610= | zE3+ldXkkCMfx53Ob6vOUZJd2QalSDKlwWBl/OVirj8= |
|   5  | iO2BxqImixcIKgVzSAqzjQ5fYfGkyXIIEolukEEjGVY= | N6ZI+4Q6Mw/ssSfn1LT+gksMhu1raovCiQQyoam0bWs= |

**It is important that you server has an IP that is not behind a CGNAT, so an actual public IP as that is the only way that the peer can contact it.**

For the peer, I use my phone and the available wireguard app on the ios app store / google play store. Then, your config on the phone should look like this (replace the placeholders with the actual values):
```
[Interface]
PrivateKey = <peer-private-key>
Address = 192.168.90.1/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server-public-ip>:33333
```
Then, you can send it to your phone. I use an online QR code generator (e.g., https://www.qr-code-generator.com/solutions/text-qr-code/) and then just scan it on my phone.

Then, assuming you have setup the above config with the correct values on your phone, you can go back to `main.go`. Basically, the only thing you'd need to change is `privateKeyServer` and `publicKeyPeer` with the appropriate keys. And now run `main.go` and then after its running, start the tunnel in the wireguard app on your phone. 

Currently, the logger is set to show debug info. You can change it to `logger.LogLevelError` if you don't wanna see debug info.

*Note: userspace-wireguard is quite slow and also some debug messages might show (missing transport layer) when you start browsing on your phone since ICMP requests are currently not handled. In the future, we can probably just ignore ICMP without any logging.*