install:
	yarn --ignore-engines
	yarn --ignore-engines build
	yarn --ignore-engines start


sassup:
	npm i sass-loader@latest

run:
	PORT=8080 \
	HOST=max.local \
	NODE_ENV=production \
	SSL_PRIV_KEY_PATH=/var/run/dashy/ssl/key.pem \
	SSL_PUB_KEY_PATH=/var/run/dashy/ssl/cert.pem \
	SSL_PORT=8443 \
	yarn --ignore-engines start

certificate:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=FR/ST=IdF/L=Paris/O=LesGrandsVoisins/OU=ParisLeNuage/CN=max.local"

certificate2:
	openssl req -new > cert.csr
	openssl rsa -in privkey.pem -out key.pem
	openssl x509 -in cert.csr -out cert.pem -req -signkey key.pem -days 100100
	cat key.pem >> cert.pem
