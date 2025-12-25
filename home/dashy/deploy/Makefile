install:
	yarn --ignore-engines
	yarn --ignore-engines build
	yarn --ignore-engines start


sassup:
	npm i sass-loader@latest

run:
	PORT=8081 \
	HOST=localhost \
	NODE_ENV=production \
	SSL_PRIV_KEY_PATH=/var/lib/acme/max.gdvoisins.com/key.pem \
	SSL_PUB_KEY_PATH=/var/lib/acme/max.gdvoisins.com/fullchain.pem \
	SSL_PORT=8443 \
	yarn --ignore-engines start
