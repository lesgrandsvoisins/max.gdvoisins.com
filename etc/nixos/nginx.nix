{ config, pkgs, lib, ... }:
let 
  oauth2IP = "max.gdvoisins.com";
in
{
 services.nginx = {
 	enable = false;
 	virtualHosts."max.gdvoisins.com" = {
 		enableACME = true;
 		forceSSL = true;
 		  locations = {
        "/" = {
          # proxyPass = "http://localhost:8080";
          # proxyPass = "https://max.gdvoisins.com:8443";
          # proxyPass = "http://127.0.0.2:4000";
          proxyPass = "https://max.local:8443";
          recommendedProxySettings = true;
          extraConfig = ''
            auth_request /oauth2/auth;
            error_page 401 =403 /oauth2/sign_in;

            # pass information via X-User and X-Email headers to backend,
            # requires running with --set-xauthrequest flag
            auth_request_set $user   $upstream_http_x_auth_request_user;
            auth_request_set $email  $upstream_http_x_auth_request_email;
            proxy_set_header X-User  $user;
            proxy_set_header X-Email $email;

            # # if you enabled --pass-access-token, this will pass the token to the backend
            # auth_request_set $token  $upstream_http_x_auth_request_access_token;
            # proxy_set_header X-Access-Token $token;

            # # if you enabled --cookie-refresh, this is needed for it to work with auth_request
            # auth_request_set $auth_cookie $upstream_http_set_cookie;
            # add_header Set-Cookie $auth_cookie;

            # # When using the --set-authorization-header flag, some provider's cookies can exceed the 4kb
            # # limit and so the OAuth2 Proxy splits these into multiple parts.
            # # Nginx normally only copies the first `Set-Cookie` header from the auth_request to the response,
            # # so if your cookies are larger than 4kb, you will need to extract additional cookies manually.
            # auth_request_set $auth_cookie_name_upstream_1 $upstream_cookie_auth_cookie_name_1;

            # # Extract the Cookie attributes from the first Set-Cookie header and append them
            # # to the second part ($upstream_cookie_* variables only contain the raw cookie content)
            # if ($auth_cookie ~* "(; .*)") {
            #     set $auth_cookie_name_0 $auth_cookie;
            #     set $auth_cookie_name_1 "auth_cookie_name_1=$auth_cookie_name_upstream_1$1";
            # }

            # # Send both Set-Cookie headers now if there was a second part
            # if ($auth_cookie_name_upstream_1) {
            #     add_header Set-Cookie $auth_cookie_name_0;
            #     add_header Set-Cookie $auth_cookie_name_1;
            # }

            # add_header Access-Control-Allow-Origin *;
            # add_header Access-Control-Allow-Origin https://max.local:8443;
            proxy_ssl_trusted_certificate /var/run/dashy/ssl/cert.pem;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
          '';
        };
        "/oauth2" = {
          # recommendedProxySettings = true;
          recommendedProxySettings = false;
          proxyPass = "https://${oauth2IP}:41443";
          extraConfig = ''
            # proxy_ssl_trusted_certificate /var/run/dashy/ssl/cert.pem;
            proxy_ssl_trusted_certificate /var/lib/acme/max.gdvoisins.com/fullchain.pem;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Auth-Request-Redirect $request_uri;
            # proxy_set_header X-Real-IP $remote_addr;
            # proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            # proxy_set_header X-Forwarded-Host $host;
            # proxy_set_header X-Forwarded-Proto $scheme;
          '';
        };
        "/oauth2/auth" = {
          proxyPass = "https://${oauth2IP}:41443";
          recommendedProxySettings = false;
          extraConfig = ''
            # proxy_ssl_trusted_certificate /var/run/dashy/ssl/cert.pem;
            proxy_ssl_trusted_certificate /var/lib/acme/max.gdvoisins.com/fullchain.pem;
            proxy_set_header Host             $host;
            proxy_set_header X-Real-IP        $remote_addr;
            proxy_set_header X-Forwarded-Uri  $request_uri;
            # nginx auth_request includes headers but not body
            proxy_set_header Content-Length   "";
            proxy_pass_request_body           off;
          '';
        };
     };
 	};
 };
}