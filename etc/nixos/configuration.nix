# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, lib, ... }:
let 
  mannRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFhMZvVw9XmqlqsN7OkxQwmick74uPEwPFE3221SbShBnjq4uPqtKWzKQkV06gABvpyMEUHkM4ZaboAwKA8BR5jrO848MdDtkVVUjTAEcXndjB5eigotSeygsa3Ym+1Bt2OVornEJlN0C09UdwOQv9Jc1KgAt/mQIySi9hNF28Z0h1DA5NhECX0jyPaRVtApx1DkP8pqFx4UqOtiXPXi1XiJxcbWKmj9Z54+grf708bOXe5qYa1Ls3wYwIkgWsvyfNPEtCTiBqEyheXu5AkFz/b6jhoUM0cZATx4r1N9s47fhiu8dLrvsfe1Ujis98s8kb231lkUbf+MQnAvtzIch83OLylOmKQmGt1+jrLHnxcXJc9qsc4TyzCF/hfaASZbYjX3XGs4PG9HzVt/wD8bkWionO49rrnC09NlwujTfoALqHN2oQX5O5RTfiPwgYd+QoILFVjdE7eWVA/TA4csHTAOxZ/I6pzWPT3ZgHFcWgA+pzmfedOKeIqLRNmoSKuhE= mannchri@mannchri";
in
{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      ./oauth2-proxy.nix
    ];

  # Bootloader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking = {
    hostName = "max"; # Define your hostname.
    hosts = { "127.0.0.2" = ["max.local"];};
  };
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  systemd.tmpfiles.rules = [
    "d /var/run/dashy/ssl 0755 dashy nginx"
    "f /var/run/dashy/ssl/key.pem 0640 dashy nginx"
    "f /var/run/dashy/ssl/cert.pem 0644 dashy nginx"
  ];

  # Enable networking
  networking.networkmanager.enable = true;

  # Set your time zone.
  time.timeZone = "Europe/Paris";

  # Select internationalisation properties.
  i18n.defaultLocale = "sr_RS@latin";

  i18n.extraLocaleSettings = {
    LC_ADDRESS = "fr_FR.UTF-8";
    LC_IDENTIFICATION = "fr_FR.UTF-8";
    LC_MEASUREMENT = "fr_FR.UTF-8";
    LC_MONETARY = "fr_FR.UTF-8";
    LC_NAME = "fr_FR.UTF-8";
    LC_NUMERIC = "fr_FR.UTF-8";
    LC_PAPER = "fr_FR.UTF-8";
    LC_TELEPHONE = "fr_FR.UTF-8";
    LC_TIME = "fr_FR.UTF-8";
  };

  # Enable the X11 windowing system.
  services.xserver.enable = true;
  virtualisation.docker = {
    enable = true;
    # Use the rootless mode - run Docker daemon as non-root user
    rootless = {
      enable = true;
      setSocketVariable = true;
    };
  };

  # Enable the XFCE Desktop Environment.
  services.xserver.displayManager.lightdm.enable = true;
  services.xserver.desktopManager.xfce.enable = true;

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "fr";
    variant = "";
  };

  # Configure console keymap
  console.keyMap = "fr";

  # Enable CUPS to print documents.
  services.printing.enable = true;

  services.hedgedoc.enable = true;
services.hedgedoc.settings = {
	host = "2a01:e34:ec2b:a450:4c4e:ec3e:9e54:6ceb";
	allowOrigin = [
		"localhost"
		"0.0.0.0"
		"[::]"
		"[::1]"
		"max.lesgrandsvoisins.com"
		"max.atelier.lesgrandsvoisins.com"
		"192.168.1.10"
		"192.168.1.222"
    "[2a01:e34:ec2b:a450:a907:5918:26ce:42ce]"
		"192.168.1.100"
	];
	protocolUseSSL = true;
	# protocolUseSSL = false;
};
security.acme.defaults.email = "max@gdvoisins.com";
security.acme.acceptTerms = true;
 services.nginx = {
# 	defaultHTTPListenPort = 80;
# 	defaultSSLListenPort = 443;
# 	defaultListen = [
# 		{ addr = "192.168.1.10"; }
# 		{ addr = "2a01:e34:ec2b:a450:4c4e:ec3e:9e54:6ceb"; }
# 	];
 	enable = true;
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

            # if you enabled --pass-access-token, this will pass the token to the backend
            auth_request_set $token  $upstream_http_x_auth_request_access_token;
            proxy_set_header X-Access-Token $token;

            # if you enabled --cookie-refresh, this is needed for it to work with auth_request
            auth_request_set $auth_cookie $upstream_http_set_cookie;
            add_header Set-Cookie $auth_cookie;

            # When using the --set-authorization-header flag, some provider's cookies can exceed the 4kb
            # limit and so the OAuth2 Proxy splits these into multiple parts.
            # Nginx normally only copies the first `Set-Cookie` header from the auth_request to the response,
            # so if your cookies are larger than 4kb, you will need to extract additional cookies manually.
            auth_request_set $auth_cookie_name_upstream_1 $upstream_cookie_auth_cookie_name_1;

            # Extract the Cookie attributes from the first Set-Cookie header and append them
            # to the second part ($upstream_cookie_* variables only contain the raw cookie content)
            if ($auth_cookie ~* "(; .*)") {
                set $auth_cookie_name_0 $auth_cookie;
                set $auth_cookie_name_1 "auth_cookie_name_1=$auth_cookie_name_upstream_1$1";
            }

            # Send both Set-Cookie headers now if there was a second part
            if ($auth_cookie_name_upstream_1) {
                add_header Set-Cookie $auth_cookie_name_0;
                add_header Set-Cookie $auth_cookie_name_1;
            }

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
        "/oauth2/" = {
          recommendedProxySettings = true;
          proxyPass = "https://max.local:41443";
          extraConfig = ''
            proxy_ssl_trusted_certificate /var/run/dashy/ssl/cert.pem;
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
          proxyPass = "https://max.local:41443";
          
          extraConfig = ''
            proxy_ssl_trusted_certificate /var/run/dashy/ssl/cert.pem;
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

  # Enable sound with pipewire.
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    #jack.enable = true;

    # use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    #media-session.enable = true;
  };

  services.sshd.enable = true;

  # Enable touchpad support (enabled default in most desktopManager).
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users = {
    max = {
      isNormalUser = true;
      description = "max";
      extraGroups = [ "networkmanager" "wheel" "docker" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ mannRSA ];
    };
    mannchri = {
      isNormalUser = true;
      description = "Chris Mann";
      extraGroups = [ "networkmanager" "wheel" "docker" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ mannRSA ];
    };
    admin = {
      isNormalUser = true;
      description = "Generic Admin User";
      extraGroups = [ "networkmanager" "wheel" "docker" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ mannRSA ];
    };
    dashy = {
      isNormalUser = true;
      description = "Dashy User";
      extraGroups = [ "nginx" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ mannRSA ];
    };

  };

  # Install firefox.
  programs.firefox.enable = true;

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    ((vim_configurable.override { }).customize {
      name = "vim";
      vimrcConfig.customRC = ''
        " your custom vimrc
        set mouse=a
        set nocompatible
        colo torte
        syntax on
        set tabstop     =2
        set softtabstop =2
        set shiftwidth  =2
        set expandtab
        set autoindent
        set smartindent
        " ...
      '';
    }
    )
    #vim
    #django-redis
    cowsay
    home-manager
    curl
    wget
    lynx
    git
    tmux
    bat
    zlib
    lzlib
    dig
    killall
    # inetutils
    pwgen
    openldap
    mysql80
    docker
    docker-compose
    #    wkhtmltopdf
    (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [
            pillow
            gunicorn
            pip
            libsass
            python-ldap
            pyscss
            django-libsass
            pylibjpeg-libjpeg
            pypdf2
            #venvShellHook
            pq
            aiosasl
            psycopg2
            django
            wagtail
            python-dotenv
            dj-database-url
            # psycopg2-binary
            django-taggit
            #wagtail-modeladmin
            ## wagtailmenus
            ## Public facing server, I think
            python-keycloak
            ## Dev
            ## djlint
            django-debug-toolbar
        ]))
    # python311Full
    # python311Packages.pip
    # python311Packages.pypdf2
    # python311Packages.python-ldap
    # python311Packages.pq
    # python311Packages.aiosasl
    # python311Packages.psycopg2
    # python311Packages.pillow
    # python311Packages.pylibjpeg-libjpeg
    busybox
    gnumake
    # For Dashy
    nodejs
    nodenv
    yarn
    openssl
  #  vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #  wget
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  networking.firewall.enable = false;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "25.05"; # Did you read the comment?

}
