# Tivan

Tivan is an utiliy to remotely retrieve logs from the Windows Event Log.
Logs can be retrieved via RPC (MSEVEN6) or SOAP (WEC).

Note that this is mostly a PoC, and therefore can contain some bugs and undocomunted limitations and requirements.

## Usage

### RPC

Tivan can pull log from Windows machines using RPC.

Example:
```
python tivan --host win10.lan --username user --password 1234 --path security --query "*"
```

### WEC

Tivan can run a SOAP server to which Windows can push logs.
The SOAP server also provides the configuration for the subscriptions which the Windows machine will retrieve.

Currently, the SOAP server requires a certificate which is signed by a seperate CA certificate.

subscriptions.ini
```
[Test]
heartbeat = PT10.000S
query = <QueryList><Query Id="0"><Select Path="Security">*</Select></Query></QueryList>
connection_retry = PT60.0S
connection_retry_total = 5
max_time = PT20.000S
content_format = RenderedText
ca_thumbprint = 45E1A985F8A5431FB0383C27FB974CBA26B84385 # Thumbprint of CA, used to sign certificate
url = HTTPS://tivan-host:5986/wsman/subscriptions/07C41EF8-1EE6-4519-86C5-47A78FB16DED/1
client = https://win10.lan:5986/wsman
username = user
password = 1234
```

Example:
```
python tivan --host 0.0.0.0 --port 8443 --cert cert.crt --key cert.key --config subscriptions.ini
```

## Contribute

1. Fork us
2. Write code
3. Send Pull Requests
