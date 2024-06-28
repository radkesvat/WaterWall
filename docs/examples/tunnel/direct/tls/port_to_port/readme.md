# SinglePort tls + tcp 


assumptions:

> port range: 23 - 65535

> foreign server address: mydomain.com

> in foreign server, the domain certificate files (fullchain.pem, privkey.pem) are present next to Waterwall

> next protocol is http/1.1 , change it if you need h2 or both

---

forward port 443 to mydomain.com:443 , then tls handshake, then to port 2083 inside the foreign server (mydomain.com)

preconnect node is added to lower the handshake time



config_client.json -> run in local server (iran) 

config_server.json -> run in foreign server (kharej)