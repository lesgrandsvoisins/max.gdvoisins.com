{ config, pkgs, lib, filestash, ... }:
let 
    oidcMaxSecret = import ./secrets/oidc-max-secret.nix;
    jwtVouchSecret = import ./secrets/jwt-vouch-secret.nix;
    oauth2IP = "192.168.1.10";
in
{
    users.users.oauth2-proxy.extraGroups = [ "nginx" "acme" "wwwrun" "dashy"];

    services.oauth2-proxy = {
      enable = true;

      # # Common configuration
      provider = "keycloak-oidc"; # or "github", "gitlab", "azure", etc.
      email.domains = ["*"]; # restrict to specific email domains
      
      # # Client credentials (register your app with the OAuth provider)
      clientID = "maxdash";
      keyFile = "/etc/.secrets/.maxdash_oauthproxy_keyfile";
      # # clientSecret = "your-client-secret";

      setXauthrequest = true;
      
      # # Cookie settings
      cookie.secret = "L053djhCZFhjakYwc25leXdFRU9xWnM2U3FMSk9HSDA="; # generate with: openssl rand -base64 32 | head -c 32 | base64
      cookie.httpOnly = true;
      cookie.secure = true;
      
      # # Additional settingsenvironment.systemPackages = with pkgs; [
      # # upstream = "http://localhost:1234"; # your backend service
      httpAddress = "${oauth2IP}:12345"; # where oauth2-proxy listens
      # nginx.proxy = "max.gdvoisins.com";
      nginx = {
        domain = "max.gdvoisins.com";
        proxy = "max.gdvoisins.com";
      };
      reverseProxy = true;
      # upstream = "http://127.0.0.1:4180";
      upstream = "file:///var/www/default";
      tls = {
        enable = true;
        certificate = "/var/lib/acme/max.gdvoisins.com/fullchain.pem";
        key = "/var/lib/acme/max.gdvoisins.com/key.pem";
        # certificate = "/var/run/dashy/ssl/cert.pem";
        # key = "/var/run/dashy/ssl/key.pem";
        httpsAddress = "${oauth2IP}:41443";
      };
      redirectURL = "https://max.gdvoisins.com/oauth2/callback";
      redeemURL = "https://keycloak.gdvoisins.com/realms/master/protocol/openid-connect/token";
      oidcIssuerUrl = "https://keycloak.gdvoisins.com/realms/master";
      loginURL = "https://keycloak.gdvoisins.com/realms/master/protocol/openid-connect/auth";
      profileURL = "https://keycloak.gdvoisins.com/realms/master/protocol/openid-connect/userinfo";
      proxyPrefix = "/oauth2";

      # validateURL = "";
      extraConfig = {
        # code-challenge-method = "S256";
      #   approval-prompt="force";
      #   client-id="seafile";
      #   client-secret-file="/etc/.secrets/.seafile_oauthproxy_keyfile";
        client-secret-file="/etc/.secrets/.maxdash_oauthproxy_keyfile";
        code-challenge-method="S256";
        cookie-csrf-expire="5m";
        cookie-csrf-per-request="true";
        cookie-domain="max.gdvoisins.com";
      #   cookie-expire="168h0m0s";
        cookie-httponly="true";
        cookie-secure="true";
      #   cookie-name="_oauth2_proxy_roses";
        cookie-name="_maxdash";
        cookie-refresh="5m";
      #   cookie-samesite="none";
        cookie-secret="NgbKPVOqtJndsvg78GuR22BwasVS1J5u";
      #   cookie-secure="false";
      #   email-domain="*" ;
        email-domains="[\"*\"]";
        scope="openid email profile";
      #   http-address=":4180";
      #   https-address=":41443";
        insecure-oidc-allow-unverified-email="true" ;
      #   oidc-issuer-url="https://key.lesgrandsvoisins.com/realms/master";
        pass-access-token="true";
        pass-authorization-header="true";
        pass-host-header="true" ;
        provider="keycloak-oidc";
        proxy-prefix="/oauth2" ;
        redirect-url="https://max.gdvoisins.com/oauth2/callback";
        request-logging="true";
        show-debug-on-error="true";
        reverse-proxy="true";
        session-store-type="cookie";
        set-authorization-header="true";
      #   set-xauthrequest="true";
        skip-provider-button="false";
      #   tls-cert-file="/var/lib/acme/roses.gdvoisins.com/full.pem";
      #   tls-key-file="/var/lib/acme/roses.gdvoisins.com/key.pem";
      #   upstream="file:///var/www/default";
      };
    };

}