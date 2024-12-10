FROM dunglas/frankenphp:1.3-php8.4

RUN apt update && apt install -y wget unzip

RUN install-php-extensions \
 pdo_mysql \
 gd \
 intl \
 zip \
 opcache \
 mongodb

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Install Security checker
RUN wget -O /usr/local/bin/local-php-security-checker "https://github.com/fabpot/local-php-security-checker/releases/download/v1.0.0/local-php-security-checker_1.0.0_linux_amd64"
RUN chmod +x /usr/local/bin/local-php-security-checker

# Set working directory
WORKDIR /home/app

# Expose port 8080
EXPOSE 8080

#######################
# Override the image  #
# ENTRYPOINT to add   #
# some logic          #
#######################
COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/entrypoint
ENTRYPOINT ["entrypoint"]