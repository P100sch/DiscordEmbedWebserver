# Discord Embed Server
Provides embeddable links for Discord.

The default folder structure is the following:
````
.
..
media/
discordEmbedServer
config.json
logins.yaml
````

Remember to substitute your own email address in the footer.gohtml template.

## Example config
````
{
"Host":"127.0.0.1",
"Port":"443",
"Hostname":"localhost",
"BaseUrl":"https://localhost",
"SslCert":"./cert.pem",
"SslKey":"./key.pem",
"LogoutTimeout":"1h",
"Auth":"simple",
"AuthConfig":{
    "FilePath":"logins.yml",
    "DBDriver":"sqlite",
    "ConnectionString":"file:./data.db",
    "ShellCommand":"./authenticate.sh"
},
"DataStore":"simple",
"DataStoreConfig":{
    "FilePath":"data.json",
    "DBDriver":"sqlite",
    "ConnectionString":"file:./data.db",
    "ShellCommand":"./datastore.sh"
},
"Logging":"file",
"LoggingConfig":{
    "FilePath":"log.txt",
    "DBDriver":"sqlite",
    "ConnectionString":"file:./data.db",
    "ShellCommand":"./log.sh"
},
"MediaPath":""
}
````
## Flags
````
--config-path=./config.json
--host=127.0.0.1
--port=443
--hostname=localhost
--url=https://localhost
--sslCert=./cert.pem
--sslKey=./key.pem
--timeout=1h
--auth=file
--auth-file=./logins.yaml
--auth-DB=sqlite
--auth-DB-Con=file:./data.db
--auth-hook=./authenticate.sh
--data-store=simple
--data-store-file=./data.json
--data-store-DB=sqlite
--data-store-DB-Con=file:./data.db
--data-store-hook=./datastore.sh
--logging=file
--logging-file=./log.txt
--logging-DB=sqlite
--logging-DB-Con=file:./data.db
--logging-hook=./log.sh
--media=./media/
````