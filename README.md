###### Fail2Ban-Filter_NGINX_bad-web-requests_failed-SSL-handshakes

## Fail2Ban filter nginx error.log to match bad web requests &amp; failed SSL handshakes

###### source nginx errors log
> /var/log/nginx/error.log

###### samples error.log records
```
{date} {time} [error] {xyz}#{xyz}: *{zyx} open() "/path/to/some/file" failed (2: No such file or directory), client: {source_ip}, server: localhost, request: "{some_request} HTTP/1.1", host: "{target_hostname}"
{date} {time} [error] {xyz}#{xyz}: *{zyx} "/path/to/some/file" is not found (2: No such file or directory), client: {source_ip}, server: localhost, request: "{some_request} HTTP/1.1", host: "{target_ip}"
{date} {time} [error] {xyz}#{xyz}: *{zyx} access forbidden by rule, client: {source_ip}, server: {target_hostname}, request: "{some_request} HTTP/1.1", host: "{target_ip}"
{date} {time} [crit] {xyz}#{xyz}: *{zyx} SSL_do_handshake() failed (SSL: error:141CF06C:SSL routines:tls_parse_ctos_key_share:bad key share) while SSL handshaking, client: {source_ip}, server: 0.0.0.0:443
```

###### Fail2Ban filter conf
```
# Fail2Ban filter nginx to match bad web requests & failed SSL handshakes
# /var/log/nginx/error.log

[INCLUDES]

[Definition]

failregex = ^ \[error\] \d+#\d+: \*\d+ (\S+ )?\"\S+\" (failed|is not found) \(2\: No such file or directory\), client\: <HOST>, server\: \S*\, request: .*?
            ^ \[error\] \d+#\d+: \*\d+ access forbidden by rule, client\: <HOST>, server\: \S*\, request: .*?
            ^ \[crit\] \d+#\d+: \*\d+ SSL_do_handshake\(\) failed \(SSL\: error\:141CF06C\:SSL routines\:tls_parse_ctos_key_share\:bad key share\) while SSL handshaking, client\: <HOST>, server\: .*?

ignoreregex =

datepattern = {^LN-BEG}%%ExY(?P<_sep>[-/.])%%m(?P=_sep)%%d[T ]%%H:%%M:%%S(?:[.,]%%f)?(?:\s*%%z)?
              ^[^\[]*\[({DATE})
              {^LN-BEG}

# DEV Notes:
# Based on nginx-botsearch filter & nginx-bad-request
# 
# Author: FM
```

###### sample jail conf
```
[nginx-error]
backend = auto
enabled = true
filter = nginx-error
logpath = /var/log/nginx/error.log
findtime = 604800
bantime = 86400
maxretry = 1
```
