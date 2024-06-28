# SinglePort reverse


assumptions:

> port: 443

> local(iran)       server address: 1.1.1.1
> foreign(kharej)   server address: 2.2.2.2

---

forward port 443 to 2.2.2.2:443 through a connection which initiated by the foreign server to port 443


port 443 is playing 2 roles here, so we white-listed the foreign server ip address in the config_client.json 

we could also use a auth node instead of ip whitelisting


# note

config_client.json -> run in foreign server  (kharej)

config_server.json -> run in local server (iran) 
