# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # Bootloader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking = {
    hostName = "max"; # Define your hostname.
    hosts = { "127.0.0.2" = ["max" "max.local"];};
  };
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

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
 		 locations."/" = {
 			proxyPass = "http://localhost:8080";
 			# proxyPass = "https://max.gdvoisins.com:8443";
 			# proxyPass = "http://127.0.0.2:4000";
 			 recommendedProxySettings = true;
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
      openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFhMZvVw9XmqlqsN7OkxQwmick74uPEwPFE3221SbShBnjq4uPqtKWzKQkV06gABvpyMEUHkM4ZaboAwKA8BR5jrO848MdDtkVVUjTAEcXndjB5eigotSeygsa3Ym+1Bt2OVornEJlN0C09UdwOQv9Jc1KgAt/mQIySi9hNF28Z0h1DA5NhECX0jyPaRVtApx1DkP8pqFx4UqOtiXPXi1XiJxcbWKmj9Z54+grf708bOXe5qYa1Ls3wYwIkgWsvyfNPEtCTiBqEyheXu5AkFz/b6jhoUM0cZATx4r1N9s47fhiu8dLrvsfe1Ujis98s8kb231lkUbf+MQnAvtzIch83OLylOmKQmGt1+jrLHnxcXJc9qsc4TyzCF/hfaASZbYjX3XGs4PG9HzVt/wD8bkWionO49rrnC09NlwujTfoALqHN2oQX5O5RTfiPwgYd+QoILFVjdE7eWVA/TA4csHTAOxZ/I6pzWPT3ZgHFcWgA+pzmfedOKeIqLRNmoSKuhE= mannchri@mannchri" ];
    };
    mannchri = {
      isNormalUser = true;
      description = "Chris Mann";
      extraGroups = [ "networkmanager" "wheel" "docker" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFhMZvVw9XmqlqsN7OkxQwmick74uPEwPFE3221SbShBnjq4uPqtKWzKQkV06gABvpyMEUHkM4ZaboAwKA8BR5jrO848MdDtkVVUjTAEcXndjB5eigotSeygsa3Ym+1Bt2OVornEJlN0C09UdwOQv9Jc1KgAt/mQIySi9hNF28Z0h1DA5NhECX0jyPaRVtApx1DkP8pqFx4UqOtiXPXi1XiJxcbWKmj9Z54+grf708bOXe5qYa1Ls3wYwIkgWsvyfNPEtCTiBqEyheXu5AkFz/b6jhoUM0cZATx4r1N9s47fhiu8dLrvsfe1Ujis98s8kb231lkUbf+MQnAvtzIch83OLylOmKQmGt1+jrLHnxcXJc9qsc4TyzCF/hfaASZbYjX3XGs4PG9HzVt/wD8bkWionO49rrnC09NlwujTfoALqHN2oQX5O5RTfiPwgYd+QoILFVjdE7eWVA/TA4csHTAOxZ/I6pzWPT3ZgHFcWgA+pzmfedOKeIqLRNmoSKuhE= mannchri@mannchri" ];
    };
    admin = {
      isNormalUser = true;
      description = "Generic Admin User";
      extraGroups = [ "networkmanager" "wheel" "docker" ];
      packages = with pkgs; [
      ];
      openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFhMZvVw9XmqlqsN7OkxQwmick74uPEwPFE3221SbShBnjq4uPqtKWzKQkV06gABvpyMEUHkM4ZaboAwKA8BR5jrO848MdDtkVVUjTAEcXndjB5eigotSeygsa3Ym+1Bt2OVornEJlN0C09UdwOQv9Jc1KgAt/mQIySi9hNF28Z0h1DA5NhECX0jyPaRVtApx1DkP8pqFx4UqOtiXPXi1XiJxcbWKmj9Z54+grf708bOXe5qYa1Ls3wYwIkgWsvyfNPEtCTiBqEyheXu5AkFz/b6jhoUM0cZATx4r1N9s47fhiu8dLrvsfe1Ujis98s8kb231lkUbf+MQnAvtzIch83OLylOmKQmGt1+jrLHnxcXJc9qsc4TyzCF/hfaASZbYjX3XGs4PG9HzVt/wD8bkWionO49rrnC09NlwujTfoALqHN2oQX5O5RTfiPwgYd+QoILFVjdE7eWVA/TA4csHTAOxZ/I6pzWPT3ZgHFcWgA+pzmfedOKeIqLRNmoSKuhE= mannchri@mannchri" ];
    };
    dashy = {
      isNormalUser = true;
      description = "Dashy User";
      extraGroups = [ "nginx" ];
      packages = with pkgs; [
        nodejs
        nodenv
        yarn
      ];
      openssh.authorizedKeys.keys = [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFhMZvVw9XmqlqsN7OkxQwmick74uPEwPFE3221SbShBnjq4uPqtKWzKQkV06gABvpyMEUHkM4ZaboAwKA8BR5jrO848MdDtkVVUjTAEcXndjB5eigotSeygsa3Ym+1Bt2OVornEJlN0C09UdwOQv9Jc1KgAt/mQIySi9hNF28Z0h1DA5NhECX0jyPaRVtApx1DkP8pqFx4UqOtiXPXi1XiJxcbWKmj9Z54+grf708bOXe5qYa1Ls3wYwIkgWsvyfNPEtCTiBqEyheXu5AkFz/b6jhoUM0cZATx4r1N9s47fhiu8dLrvsfe1Ujis98s8kb231lkUbf+MQnAvtzIch83OLylOmKQmGt1+jrLHnxcXJc9qsc4TyzCF/hfaASZbYjX3XGs4PG9HzVt/wD8bkWionO49rrnC09NlwujTfoALqHN2oQX5O5RTfiPwgYd+QoILFVjdE7eWVA/TA4csHTAOxZ/I6pzWPT3ZgHFcWgA+pzmfedOKeIqLRNmoSKuhE= mannchri@mannchri" ];
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
