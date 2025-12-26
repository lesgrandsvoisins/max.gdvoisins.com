{ config, pkgs, lib, caddy-ui-lesgv, ... }:
let 
  caddy-ui-lesgrandsvoisins = pkgs.callPackage ./derivations/caddy-ui-lesgrandsvoisins.nix {};
in
{ 

  systemd.tmpfiles.rules = [
    "d /etc/caddy 0755 caddy users"
    "f /etc/caddy/cady.env 0640 caddy users"
  ];

  services.caddy = {
    enable = true;
    package = pkgs.caddy.withPlugins {
      plugins = ["github.com/greenpau/caddy-security@v1.1.31"];
      hash = "sha256-6WJ403U6XbaNfncIvEJEwUc489yyRhv4jP7H/RVJWlM=";
    };

    environmentFile = "/etc/caddy/caddy.env";
    email = "hostmaster@lesgrandsvoisins.com";

    globalConfig = ''
      order authenticate before respond
      order authorize before basicauth

      security {
        oauth identity provider keycloak {
          driver generic
          realm keycloak
          client_id {env.KEYCLOAK_CLIENT_ID}
          client_secret {env.KEYCLOAK_CLIENT_SECRET}
          scopes profile openid email 
          extract all from userinfo
          metadata_url https://keycloak.gdvoisins.com/realms/master/.well-known/openid-configuration
        }

        authentication portal keygdvoisinscom {
          crypto default token lifetime 3600
          crypto key sign-verify {env.JWT_SHARED_KEY}
          enable identity provider keycloak
          cookie domain gdvoisins.com
          ui {
            links {
              "Copyparty" https://max.gdvoisins.com:443/ icon "las la-star"
              "Moi" "/whoami" icon "las la-user"
            }
            # custom html header path "${caddy-ui-lesgrandsvoisins}/assets/html/header-lesgrandsvoisins.html"
            # template generic "${caddy-ui-lesgrandsvoisins}/assets/portal/templates/lesgrandsvoisins/generic.template"
            template login "${caddy-ui-lesgrandsvoisins}/assets/portal/templates/lesgrandsvoisins/login.template"
            logo url "${caddy-ui-lesgrandsvoisins}/assets/images/logo-lesgrandsvoisins-800-400-white.png"
            logo description "Les Grands Voisins"
            # static_asset "${caddy-ui-lesgrandsvoisins}/assets/css/lesgrandsvoisins.css" "text/css" "assets/css/lesgrandsvoisins.css"
            # static_asset "${caddy-ui-lesgrandsvoisins}/assets/images/logo-lesgrandsvoisins-800-400-white.png" "text/css" "assets/images/logo-lesgrandsvoisins-800-400-white.png"
            # static_asset "${caddy-ui-lesgrandsvoisins}/assets/images/favicon.png" "image/png" "assets/images/logo-lesgrandsvoisins-800-400-white.png"
            static_asset "assets/images/logo-lesgrandsvoisins-800-400-white.png" "text/css" "assets/images/logo-lesgrandsvoisins-800-400-white.png"
            static_asset "assets/images/favicon.png" "image/png" "assets/images/logo-lesgrandsvoisins-800-400-white.png"
          }

          transform user {
            match origin keycloak
            action add role authp/user
          }
        }

        authorization policy identifiedpolicy {
          set auth url https://auth.max.gdvoisins.com
          allow roles guest authp/admin authp/user
          crypto key verify {env.JWT_SHARED_KEY}
          set user identity subject
          inject headers with claims
          inject header "X-Username" from "userinfo|preferred_username"
        }

        authorization policy userpolicy {
          set auth url https://auth.max.gdvoisins.com
          allow roles authp/admin authp/user
          crypto key verify {env.JWT_SHARED_KEY}
          inject headers with claims
        }

      }
    '';

    virtualHosts = {
      "auth.max.gdvoisins.com" = {
        extraConfig = ''
          authenticate with keygdvoisinscom
          respond "auth.max.gdvoisins.com is running"
        '';
      };
      "max.gdvoisins.com" = {
        extraConfig = ''
          authorize with identifiedpolicy
          reverse_proxy https://max.local:8443 {
            transport http {
              # tls_server_name max.local
              # tls_insecure_skip_verify
              tls_client_auth /var/run/dashy/ssl/cert.pem /var/run/dashy/ssl/key.pem
            }
          }
        '';
      };
    };
  };
}