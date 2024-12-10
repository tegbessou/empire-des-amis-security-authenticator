#!/bin/bash
set -e

uid=$(stat -c %u /home/app)
gid=$(stat -c %g /home/app)

if [ $uid != 0 ] || [ $gid != 0 ]; then
    # Change www-data's uid & guid to be the same as directory in host
    sed -ie "s/`id -u www-data`:`id -g www-data`/$uid:$gid/g" /etc/passwd

    mkdir -p /var/log/php && chown -Rf $uid:$gid /var/log/php && chown -Rf $uid:$gid /config/composer && chown -Rf $uid:$gid /var/www/
fi

exec docker-php-entrypoint --config /etc/caddy/Caddyfile --adapter caddyfile