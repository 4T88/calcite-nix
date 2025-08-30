# nixos minecraft server config
# 
# optimized configuration for dedicated minecraft servers
# includes velocity proxy, multiple paper servers, automated backups
# 
# IMPORTANT: this config includes sensitive default values that need changing:
# 
# 1. SECURITY SETTINGS TO CHANGE:
#    - networking.hostName (line 108)
#    - networking.domain (line 109) 
#    - services.openssh.ports (line 172) - change from default SSH port
#    - services.openssh.settings.AllowUsers (line 191) - change username
#    - users.users.YOUR_USERNAME (line 137) - change from default username
#    - time.timeZone (line 121) - set your timezone
# 
# 2. FIREWALL PORTS TO REVIEW (lines 113-127):
#    - remove unused ports for better security
#    - minecraft ports: 25565-25580 (standard)
#    - web ports: 80, 443 (if running web services)
#    - custom ports: review and remove if not needed
# 
# 3. HARDWARE OPTIMIZATION:
#    - adjust CPU core assignments in taskset commands (lines 311, 339, 365)
#    - modify memory allocations (-Xms/-Xmx values) based on your RAM
#    - update disk paths for your storage setup (line 751)
# 
# 4. OPTIONAL SERVICES TO DISABLE:
#    - FTP server (line 219) - remove if not needed
#    - fail2ban specific jails - customize for your needs
# 
# after editing, run: sudo nixos-rebuild switch

{ config, pkgs, lib, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  # Boot configuration - optimized for performance
  boot = {
    loader = {
      systemd-boot = {
        enable = true;
        configurationLimit = 5;  # Keep only 5 boot entries
      };
      efi.canTouchEfiVariables = true;
      timeout = 3;
    };
    kernelPackages = pkgs.linuxPackages_latest;
    
    # Fixed kernel parameters - removed problematic CPU isolation
    kernelParams = [
      "elevator=mq-deadline"
      "mitigations=auto"
      "quiet"
      "intel_pstate=performance"
      "nohz=off"
    ];

    # Optimized sysctl parameters
    kernel.sysctl = {
      # Memory management - optimized for gaming servers
      "vm.swappiness" = 0;  # Changed from 1 - avoid swap for gaming
      "vm.dirty_ratio" = 10;  # Reduced from 15 for better responsiveness
      "vm.dirty_background_ratio" = 3;  # Reduced from 5
      "vm.vfs_cache_pressure" = 50;
      "vm.zone_reclaim_mode" = 0;
      "vm.page-cluster" = 0;
      
      # Better Java/server performance
      "kernel.sched_migration_cost_ns" = 5000000;
      "kernel.sched_autogroup_enabled" = 0;
      
      # Network performance - high throughput optimization
      "net.core.rmem_max" = 536870912;
      "net.core.wmem_max" = 536870912;
      "net.ipv4.tcp_rmem" = "4096 262144 536870912";
      "net.ipv4.tcp_wmem" = "4096 262144 536870912";
      "net.core.netdev_max_backlog" = 50000;
      "net.core.netdev_budget" = 600;
      "net.core.netdev_budget_usecs" = 5000;
      
      # TCP optimization for low latency
      "net.ipv4.tcp_congestion_control" = "bbr";
      "net.core.default_qdisc" = "fq_codel";
      "net.ipv4.tcp_low_latency" = 1;
      "net.ipv4.tcp_fastopen" = 3;
      "net.ipv4.tcp_no_delay_ack" = 1;
      "net.ipv4.tcp_slow_start_after_idle" = 0;
      "net.ipv4.tcp_mtu_probing" = 1;
      
      # Connection handling optimization
      "net.ipv4.tcp_keepalive_time" = 600;
      "net.ipv4.tcp_keepalive_intvl" = 60;
      "net.ipv4.tcp_keepalive_probes" = 3;
      "net.ipv4.tcp_max_syn_backlog" = 16384;
      "net.core.somaxconn" = 65535;
      "net.ipv4.tcp_max_tw_buckets" = 2000000;
      "net.ipv4.tcp_tw_reuse" = 1;
      "net.ipv4.tcp_fin_timeout" = 10;
      
      # File system optimization
      "fs.file-max" = 2097152;
      "fs.nr_open" = 1048576;
      "fs.inotify.max_user_watches" = 524288;
      "fs.inotify.max_user_instances" = 512;
      
      # Security hardening
      "net.ipv4.conf.all.send_redirects" = 0;
      "net.ipv4.conf.default.send_redirects" = 0;
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.accept_source_route" = 0;
      "net.ipv4.conf.default.accept_source_route" = 0;
      "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
      "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
      "net.ipv4.tcp_syncookies" = 1;
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.conf.all.log_martians" = 1;
      "net.ipv4.conf.default.log_martians" = 1;
      
      # Netfilter optimization
      "net.netfilter.nf_conntrack_max" = 4194304;
      "net.netfilter.nf_conntrack_tcp_timeout_established" = 1800;
      "net.netfilter.nf_conntrack_tcp_timeout_time_wait" = 30;
      "net.ipv4.ip_local_port_range" = "1024 65535";
      "net.netfilter.nf_conntrack_buckets" = 1048576;
    };

    # Optimized temporary filesystem
    tmp = {
      cleanOnBoot = true;
      useTmpfs = true;
      tmpfsSize = "25%";
    };
    
    # Security modules blacklist
    blacklistedKernelModules = [
      "dccp" "sctp" "rds" "tipc" "cramfs" "freevxfs" "jffs2"
      "hfs" "hfsplus" "squashfs" "udf" "bluetooth" "btusb"
    ];
  };

  # Networking configuration
  networking = {
    hostName = "YOUR_HOSTNAME_HERE"; # CHANGE THIS
    domain = "yourdomain.com"; # CHANGE THIS  
    networkmanager.enable = true;
    
    # Optimized firewall
    firewall = {
      enable = true;
      allowedTCPPorts = [ 
        YOUR_SSH_PORT  # CHANGE SSH PORT NUMBER
        80      # HTTP
        443     # HTTPS
        445     # SMB
        2022    # Custom
        8080    # HTTP Alt
        19132   # Bedrock
        21      # FTP Control
        4567    # Spark profiler
      ];
      allowedUDPPorts = [
        24454   # Custom
        19132   # Bedrock
      ];
      allowedTCPPortRanges = [
        { from = 25565; to = 25580; }  # All Minecraft ports
        { from = 21000; to = 21010; }  # FTP Passive Mode
      ];
      allowedUDPPortRanges = [
        { from = 25565; to = 25580; }
      ];
    };
  };

  # Time and locale
  time.timeZone = "Europe/Bucharest"; # CHANGE TO YOUR TIMEZONE
  
  services.timesyncd = {
    enable = true;
    servers = [ 
      "0.pool.ntp.org" # CHANGE TO LOCAL NTP SERVERS
      "1.pool.ntp.org"
      "2.pool.ntp.org"
      "3.pool.ntp.org"
    ];
  };

  i18n = {
    defaultLocale = "en_US.UTF-8";
    extraLocaleSettings = {
      LC_ADDRESS = "en_US.UTF-8"; # CHANGE TO YOUR LOCALE
      LC_IDENTIFICATION = "en_US.UTF-8";
      LC_MEASUREMENT = "en_US.UTF-8";
      LC_MONETARY = "en_US.UTF-8";
      LC_NAME = "en_US.UTF-8";
      LC_NUMERIC = "en_US.UTF-8";
      LC_PAPER = "en_US.UTF-8";
      LC_TELEPHONE = "en_US.UTF-8";
      LC_TIME = "en_US.UTF-8";
    };
  };

  services.xserver.xkb = {
    layout = "us";
    variant = "";
  };

  # User management - FIXED permissions
  users = {
    users.YOUR_USERNAME = { # CHANGE USERNAME
      isNormalUser = true;
      description = "Server Administrator";
      extraGroups = [ "networkmanager" "wheel" "docker" "minecraft" ];
      shell = pkgs.bash;
    };

    users.minecraft = {
      isSystemUser = true;
      group = "minecraft";
      home = "/var/lib/gamedata/minecraft";
      createHome = true;
    };

    groups.minecraft = {
      members = [ "YOUR_USERNAME" ]; # CHANGE USERNAME
    };
  };

  # Security configuration
  security = {
    sudo = {
      enable = true;
      wheelNeedsPassword = true;
      execWheelOnly = true;
      configFile = ''
        Defaults timestamp_timeout=5
        Defaults lecture=never
        Defaults pwfeedback
        Defaults env_reset
        Defaults secure_path="/nix/var/nix/profiles/default/bin:/nix/var/nix/profiles/default/sbin:/run/current-system/sw/bin:/run/current-system/sw/sbin"
      '';
    };

    apparmor = {
      enable = true;
      killUnconfinedConfinables = true;
    };

    # Disable unused PAM services for better security
    pam.services = {
      su.requireWheel = true;
    };
  };

  # SSH configuration - hardened
  services.openssh = {
    enable = true;
    ports = [ YOUR_SSH_PORT ]; # CHANGE SSH PORT
    settings = {
      PasswordAuthentication = true;
      PermitRootLogin = "no";
      PubkeyAuthentication = true;
      Protocol = 2;
      MaxAuthTries = 3;
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
      PermitEmptyPasswords = false;
      AllowUsers = [ "YOUR_USERNAME" ]; # CHANGE USERNAME
      X11Forwarding = false;
      AllowAgentForwarding = false;
      AllowTcpForwarding = false;
      PermitTunnel = "no";
      MaxStartups = "10:30:60";
      LoginGraceTime = 30;
      
      Ciphers = [ 
        "chacha20-poly1305@openssh.com"
        "aes256-gcm@openssh.com" 
        "aes128-gcm@openssh.com" 
        "aes256-ctr" 
        "aes192-ctr" 
        "aes128-ctr" 
      ];
      Macs = [
        "hmac-sha2-256-etm@openssh.com"
        "hmac-sha2-512-etm@openssh.com"
        "hmac-sha2-256"
        "hmac-sha2-512"
      ];
      KexAlgorithms = [
        "curve25519-sha256@libssh.org"
        "diffie-hellman-group16-sha512"
        "diffie-hellman-group18-sha512"
        "diffie-hellman-group14-sha256"
      ];
    };
    
    banner = ''
      minecraft server - authorized access only
      all connections are monitored and logged
    '';
  };

  # FTP configuration - optimized (OPTIONAL - remove if not needed)
  services.vsftpd = {
    enable = true;
    writeEnable = true;
    localUsers = true;
    userlist = [ "YOUR_USERNAME" ]; # CHANGE USERNAME
    userlistEnable = true;
    userlistDeny = false;
    anonymousUser = false;
    anonymousUserNoPassword = false;
    localRoot = "/var/lib/gamedata";
    chrootlocalUser = true;
    allowWriteableChroot = true;
    
    extraConfig = ''
      # Network settings
      listen=YES
      listen_ipv6=NO
      pasv_enable=YES
      pasv_min_port=21000
      pasv_max_port=21010
      port_enable=YES
      connect_from_port_20=YES
      
      # Performance settings
      idle_session_timeout=300
      data_connection_timeout=300
      max_clients=20
      max_per_ip=5
      
      # Security settings
      ssl_enable=NO
      force_local_data_ssl=NO
      force_local_logins_ssl=NO
      
      # Logging
      xferlog_enable=YES
      xferlog_std_format=YES
      log_ftp_protocol=YES
      
      # File permissions
      file_open_mode=0644
      local_umask=022
      
      # Directory listings
      use_localtime=YES
      hide_ids=YES
    '';
  };

  # Fail2ban - enhanced protection
  services.fail2ban = {
    enable = true;
    maxretry = 3;
    ignoreIP = [
      "127.0.0.0/8"
      "192.168.0.0/16"
      "10.0.0.0/8"
      "172.16.0.0/12"
    ];
    bantime = "4h";
    bantime-increment = {
      enable = true;
      maxtime = "168h";  # 1 week
      factor = "2";
    };
    
    jails = {
      sshd = {
        settings = {
          enabled = true;
          port = "YOUR_SSH_PORT"; # CHANGE TO MATCH SSH PORT
          filter = "sshd";
          maxretry = 3;
          bantime = 14400;  # 4 hours
          findtime = 600;
        };
      };
      
      vsftpd = {
        settings = {
          enabled = true;
          port = "21";
          filter = "vsftpd";
          maxretry = 3;
          bantime = 7200;  # 2 hours
          findtime = 600;
        };
      };
    };
  };

  # Docker configuration - optimized
  virtualisation.docker = {
    enable = true;
    enableOnBoot = true;
    storageDriver = "overlay2";
    daemon.settings = {
      data-root = "/var/lib/gamedata/docker";
      log-driver = "json-file";
      log-opts = {
        max-size = "100m";
        max-file = "3";
      };
      storage-driver = "overlay2";
      experimental = false;
      live-restore = true;
      default-ulimits = {
        nofile = {
          name = "nofile";
          hard = 65536;
          soft = 65536;
        };
        nproc = {
          name = "nproc";
          hard = 8192;
          soft = 4096;
        };
      };
    };
    autoPrune = {
      enable = true;
      dates = "weekly";
      flags = [ "--all" "--filter" "until=72h" "--volumes" ];
    };
  };

  # Minecraft Servers Configuration - FIXED and OPTIMIZED
  systemd.services = {
    # Velocity Proxy Server - ADJUST CPU CORES FOR YOUR SYSTEM
    minecraft-velocity = {
      description = "Velocity Minecraft Proxy Server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      
      serviceConfig = {
        Type = "simple";
        User = "minecraft";
        Group = "minecraft";
        WorkingDirectory = "/var/lib/gamedata/minecraft/velocity";
        # CHANGE: adjust -c 0 to use available CPU core
        ExecStart = "${pkgs.util-linux}/bin/taskset -c 0 ${pkgs.temurin-bin-21}/bin/java -server -Xms512M -Xmx512M -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=4M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -jar server.jar";
        Restart = "always";
        RestartSec = "10";
        StandardOutput = "journal";
        StandardError = "journal";
        LimitNOFILE = 65536;
        KillSignal = "SIGTERM";
        TimeoutStopSec = "30s";
      };
    };

    # Main Minecraft Server - ADJUST MEMORY AND CPU FOR YOUR SYSTEM
    minecraft-main = {
      description = "Main Minecraft Server (Paper 1.21.3)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      
      serviceConfig = {
        Type = "simple";
        User = "minecraft";
        Group = "minecraft";
        WorkingDirectory = "/var/lib/gamedata/minecraft/main";
        # CHANGE: adjust -c 0-5 for your CPU cores and -Xms/-Xmx for your RAM
        ExecStart = "${pkgs.util-linux}/bin/taskset -c 0-5 ${pkgs.temurin-bin-21}/bin/java -server -Xms20G -Xmx20G -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:ParallelGCThreads=6 -XX:ConcGCThreads=3 -XX:G1ConcRefinementThreads=6 -XX:MaxGCPauseMillis=50 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=40 -XX:G1MaxNewSizePercent=50 -XX:G1HeapRegionSize=16M -XX:G1ReservePercent=15 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=10 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -XX:+UseLargePages -XX:+UseTransparentHugePages -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -jar server.jar --nogui";
        Restart = "always";
        RestartSec = "10";
        StandardOutput = "journal";
        StandardError = "journal";
        LimitNOFILE = 65536;
        LimitMEMLOCK = "infinity";
        KillSignal = "SIGTERM";
        TimeoutStopSec = "30s";
      };
    };

    # Fallback Minecraft Server - ADJUST CPU CORE FOR YOUR SYSTEM  
    minecraft-fallback = {
      description = "Fallback Minecraft Server (Paper 1.21.3)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      
      serviceConfig = {
        Type = "simple";
        User = "minecraft";
        Group = "minecraft";
        WorkingDirectory = "/var/lib/gamedata/minecraft/fallback";
        # CHANGE: adjust -c 5 to use available CPU core
        ExecStart = "${pkgs.util-linux}/bin/taskset -c 5 ${pkgs.temurin-bin-21}/bin/java -server -Xms512M -Xmx512M -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=4M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -jar server.jar --nogui";
        Restart = "always";
        RestartSec = "10";
        StandardOutput = "journal";
        StandardError = "journal";
        LimitNOFILE = 65536;
        KillSignal = "SIGTERM";
        TimeoutStopSec = "30s";
      };
    };

    # Automated maintenance service
    cleanup-system = {
      description = "System Cleanup Service";
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        ExecStart = pkgs.writeShellScript "cleanup-system" ''
          echo "Starting comprehensive system cleanup..."
          
          # Clean temporary files
          find /tmp -type f -atime +3 -delete 2>/dev/null || true
          find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
          
          # Clean old logs
          journalctl --vacuum-time=2weeks
          journalctl --vacuum-size=500M
          
          # Clean Minecraft crash reports older than 30 days
          find /var/lib/gamedata/minecraft/*/crash-reports -name "*.txt" -mtime +30 -delete 2>/dev/null || true
          
          # Clean old world backups (keep last 5)
          for server in velocity main fallback; do
            if [ -d "/var/lib/gamedata/minecraft/$server/backups" ]; then
              cd "/var/lib/gamedata/minecraft/$server/backups"
              ls -t *.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
            fi
          done
          
          # Docker cleanup
          docker system prune -af --volumes 2>/dev/null || true
          
          # NixOS cleanup - remove old generations and orphaned packages
          echo "Cleaning NixOS generations..."
          # Remove system generations older than 5 days
          nix-env --delete-generations +5 -p /nix/var/nix/profiles/system
          
          # Remove user profile generations older than 5 days
          for user_profile in /nix/var/nix/profiles/per-user/*/profile; do
            if [ -e "$user_profile" ]; then
              nix-env --delete-generations +5 -p "$user_profile" 2>/dev/null || true
            fi
          done
          
          # Clean boot entries (keep last 5 generations)
          /run/current-system/bin/switch-to-configuration boot 2>/dev/null || true
          
          # Nix store cleanup
          echo "Optimizing Nix store..."
          nix-collect-garbage -d
          nix-store --optimise
          
          # Remove broken symlinks from Nix store
          find /nix/store -maxdepth 1 -type l ! -exec test -e {} \; -delete 2>/dev/null || true
          
          # Clean package manager caches
          rm -rf /root/.cache/* 2>/dev/null || true
          rm -rf /home/*/.cache/* 2>/dev/null || true
          
          # Clean NixOS build artifacts
          rm -rf /tmp/nix-build-* 2>/dev/null || true
          rm -rf /tmp/nix-shell-* 2>/dev/null || true
          
          # Clean old kernel modules and firmware
          find /lib/modules -maxdepth 1 -type d -name "*" ! -name "$(uname -r)" -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
          
          # Clean systemd journal
          systemctl restart systemd-journal-flush.service 2>/dev/null || true
          
          # Clean font cache
          fc-cache -f 2>/dev/null || true
          
          # Clean shared library cache  
          ldconfig 2>/dev/null || true
          
          # Clean package metadata
          rm -rf /var/cache/nixos/* 2>/dev/null || true
          
          # Remove old NixOS configurations from /etc (keep last 3)
          cd /etc/nixos || true
          if [ -d versions ]; then
            cd versions
            ls -t configuration.nix.* 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true
          fi
          
          echo "System cleanup completed!"
          
          # Show cleanup summary
          echo "=== CLEANUP SUMMARY ==="
          echo "Disk usage after cleanup:"
          df -h / /nix /var/lib/gamedata 2>/dev/null || true
          echo ""
          echo "Available NixOS generations:"
          nix-env --list-generations -p /nix/var/nix/profiles/system | tail -5
          echo ""
          echo "Nix store size:"
          du -sh /nix/store 2>/dev/null || echo "Unable to calculate /nix/store size"
        '';
      };
    };

    # Automatic backup service
    minecraft-backup = {
      description = "Minecraft Server Backup";
      serviceConfig = {
        Type = "oneshot";
        User = "minecraft";
        Group = "minecraft";
        ExecStart = pkgs.writeShellScript "minecraft-backup" ''
          BACKUP_DIR="/var/lib/gamedata/minecraft/backups"
          DATE=$(date +%Y%m%d_%H%M%S)
          
          mkdir -p "$BACKUP_DIR"
          cd /var/lib/gamedata/minecraft
          
          echo "Creating backup: minecraft_backup_$DATE.tar.gz"
          tar --exclude="backups" --exclude="server.jar" --exclude="cache" --exclude="logs" \
              -czf "$BACKUP_DIR/minecraft_backup_$DATE.tar.gz" \
              velocity/ main/ fallback/ 2>/dev/null || true
          
          # Keep only last 5 backups
          cd "$BACKUP_DIR"
          ls -t minecraft_backup_*.tar.gz | tail -n +6 | xargs rm -f 2>/dev/null || true
          
          echo "Backup completed: $BACKUP_DIR/minecraft_backup_$DATE.tar.gz"
        '';
      };
    };

    # Health check service
    minecraft-healthcheck = {
      description = "Minecraft Servers Health Check";
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        ExecStart = pkgs.writeShellScript "minecraft-healthcheck" ''
          echo "=== Minecraft Health Check $(date) ==="
          
          # Check if services are running
          for service in minecraft-velocity minecraft-main minecraft-fallback; do
            if systemctl is-active --quiet $service; then
              echo "✓ $service is running"
            else
              echo "✗ $service is not running - attempting restart"
              systemctl restart $service
            fi
          done
          
          # Check disk space
          DISK_USAGE=$(df /var/lib/gamedata | tail -1 | awk '{print $5}' | sed 's/%//')
          if [ "$DISK_USAGE" -gt 85 ]; then
            echo "⚠ WARNING: Disk usage is $DISK_USAGE% - running cleanup"
            systemctl start cleanup-system.service
          fi
          
          # Check memory usage
          MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
          if [ "$MEM_USAGE" -gt 90 ]; then
            echo "⚠ WARNING: Memory usage is $MEM_USAGE%"
          fi
          
          echo "Health check completed."
        '';
      };
    };

    # Restart service for main server
    minecraft-main-restart = {
      description = "Restart Main Minecraft Server";
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        ExecStart = pkgs.writeShellScript "minecraft-main-restart" ''
          echo "Restarting main Minecraft server..."
          systemctl restart minecraft-main.service
          sleep 5
          if systemctl is-active --quiet minecraft-main.service; then
            echo "Main server restarted successfully"
          else
            echo "Main server restart failed"
          fi
        '';
      };
    };
  };

  # FIXED tmpfiles rules for proper permissions
  systemd.tmpfiles.rules = [
    "d /var/lib/gamedata/minecraft 0775 minecraft minecraft -"
    "d /var/lib/gamedata/minecraft/velocity 0775 minecraft minecraft -"
    "d /var/lib/gamedata/minecraft/main 0775 minecraft minecraft -"
    "d /var/lib/gamedata/minecraft/fallback 0775 minecraft minecraft -"
    "d /var/lib/gamedata/minecraft/backups 0775 minecraft minecraft -"
    "Z /var/lib/gamedata/minecraft 0775 minecraft minecraft -"
    # Add ACL rules to allow user full access
    "a+ /var/lib/gamedata/minecraft - - - - u:YOUR_USERNAME:rwx,d:u:YOUR_USERNAME:rwx" # CHANGE USERNAME
    "a+ /var/lib/gamedata/minecraft/velocity - - - - u:YOUR_USERNAME:rwx,d:u:YOUR_USERNAME:rwx"  
    "a+ /var/lib/gamedata/minecraft/main - - - - u:YOUR_USERNAME:rwx,d:u:YOUR_USERNAME:rwx"
    "a+ /var/lib/gamedata/minecraft/fallback - - - - u:YOUR_USERNAME:rwx,d:u:YOUR_USERNAME:rwx"
    "a+ /var/lib/gamedata/minecraft/backups - - - - u:YOUR_USERNAME:rwx,d:u:YOUR_USERNAME:rwx"
  ];

  # Automated timers
  systemd.timers = {
    cleanup-system = {
      description = "Run system cleanup weekly";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "weekly";
        Persistent = true;
        RandomizedDelaySec = "1h";
      };
    };

    minecraft-backup = {
      description = "Backup Minecraft servers daily";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "02:00";
        Persistent = true;
        RandomizedDelaySec = "30m";
      };
    };

    minecraft-healthcheck = {
      description = "Health check every 15 minutes";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "*:0/15";
        Persistent = true;
      };
    };

    minecraft-main-restart = {
      description = "Restart main Minecraft server daily at 3 AM";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "03:00";
        Persistent = true;
      };
    };
  };

  # Package configuration
  nixpkgs.config.allowUnfree = true;
  
  environment.systemPackages = with pkgs; [
    # Editors
    vim
    nano
    
    # Network tools
    wget
    curl
    nettools
    nmap
    tcpdump
    wireshark-cli
    
    # System monitoring
    htop
    btop
    iotop
    nethogs
    lsof
    psmisc
    sysstat
    perf-tools
    
    # File management
    tree
    unzip
    zip
    lf
    rsync
    
    # Development
    git
    jq  # For JSON parsing in update scripts
    
    # Containers
    docker-compose
    lazydocker
    
    # System info
    fastfetch
    
    # Security
    lynis
    chkrootkit
    
    # Java
    temurin-bin-21
    
    # Terminal multiplexers
    screen
    tmux
    
    # Network optimization
    ethtool
    
    # Archive tools
    p7zip
    gzip
    bzip2
    
    # System utilities
    killall
    which
    file
    
    # ACL and permission tools
    acl
    attr
  ];

  # Custom management scripts with permission management
  environment.shellAliases = {
    # Server management commands
    velocityreboot = "sudo systemctl restart minecraft-velocity.service";
    mainreboot = "sudo systemctl restart minecraft-main.service";
    fallbackreboot = "sudo systemctl restart minecraft-fallback.service";
    
    velocitystop = "sudo systemctl stop minecraft-velocity.service";
    mainstop = "sudo systemctl stop minecraft-main.service";
    fallbackstop = "sudo systemctl stop minecraft-fallback.service";
    
    velocitystart = "sudo systemctl start minecraft-velocity.service";
    mainstart = "sudo systemctl start minecraft-main.service";  
    fallbackstart = "sudo systemctl start minecraft-fallback.service";
    
    velocitystatus = "sudo systemctl status minecraft-velocity.service";
    mainstatus = "sudo systemctl status minecraft-main.service";
    fallbackstatus = "sudo systemctl status minecraft-fallback.service";
    
    # Console access commands
    velocityconsole = "sudo journalctl -u minecraft-velocity -f";
    mainconsole = "sudo journalctl -u minecraft-main -f";
    fallbackconsole = "sudo journalctl -u minecraft-fallback -f";
    
    # Log access
    velocitylogs = "sudo tail -f /var/lib/gamedata/minecraft/velocity/logs/proxy.log";
    mainlogs = "sudo tail -f /var/lib/gamedata/minecraft/main/logs/latest.log";
    fallbacklogs = "sudo tail -f /var/lib/gamedata/minecraft/fallback/logs/latest.log";
    
    # Quick navigation
    cdvelocity = "cd /var/lib/gamedata/minecraft/velocity";
    cdmain = "cd /var/lib/gamedata/minecraft/main";
    cdfallback = "cd /var/lib/gamedata/minecraft/fallback";
    cdminecraft = "cd /var/lib/gamedata/minecraft";
    
    # System monitoring
    serverstats = "btop";
    netmon = "sudo nethogs";
    diskmon = "sudo iotop";
    
    # Maintenance commands
    cleanall = "sudo systemctl start cleanup-system.service";
    updateall = "sudo nixos-rebuild switch --upgrade";
    
    # Permission management commands
    fixperms = "sudo systemd-tmpfiles --create";
    checkperms = "getfacl /var/lib/gamedata/minecraft";
    
    # Quick server overview with cleanup info
    serveroverview = ''
      echo "=== Minecraft Server Status ===" && \
      sudo systemctl is-active minecraft-velocity minecraft-main minecraft-fallback && \
      echo "" && \
      echo "=== System Resources ===" && \
      free -h && \
      echo "" && \
      df -h /var/lib/gamedata && \
      echo "" && \
      echo "=== NixOS Generations ===" && \
      nix-env --list-generations -p /nix/var/nix/profiles/system | tail -3 && \
      echo "" && \
      echo "=== Nix Store Size ===" && \
      du -sh /nix/store 2>/dev/null || echo "Unable to calculate"
    '';
    
    # Advanced cleanup commands
    deepclean = "sudo systemctl start cleanup-system.service && echo 'Deep cleanup started - check logs with: sudo journalctl -u cleanup-system -f'";
    nixclean = "sudo nix-collect-garbage -d && sudo nix-store --optimise";
    bootclean = "sudo /run/current-system/bin/switch-to-configuration boot";
    
    # System information
    sysinfo = ''
      echo "=== System Information ===" && \
      fastfetch && \
      echo "" && \
      echo "=== Disk Usage ===" && \
      df -h && \
      echo "" && \
      echo "=== Memory Usage ===" && \
      free -h && \
      echo "" && \
      echo "=== Active Services ===" && \
      sudo systemctl list-units --type=service --state=active | grep minecraft
    '';
  };

  # Power management - performance oriented
  powerManagement = {
    cpuFreqGovernor = "performance";
    powertop.enable = false;
  };
  
  # Disable unnecessary services
  services = {
    avahi.enable = false;
    printing.enable = false;
    udisks2.enable = false;
    power-profiles-daemon.enable = false;
    fwupd.enable = false;
    packagekit.enable = false;
  };
  
  # Optimized udev rules
  services.udev.extraRules = ''
    # SSD optimization
    ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
    ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/read_ahead_kb}="128"
    ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/nr_requests}="256"
    
    # HDD optimization
    ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
    ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="1", ATTR{queue/read_ahead_kb}="1024"
    
    # Network interface optimization
    ACTION=="add", SUBSYSTEM=="net", KERNEL=="e*", RUN+="${pkgs.ethtool}/bin/ethtool -K %k tso on gso on gro on"
  '';

  # File system configuration with ACL support
  # CHANGE: update disk path for your storage setup
  fileSystems."/var/lib/gamedata" = {
    device = "/dev/YOUR_DISK_DEVICE"; # CHANGE THIS TO YOUR ACTUAL DISK DEVICE
    fsType = "ext4";
    options = [ "defaults" "noatime" "nodiratime" "discard" "acl" "user_xattr" ];
  };

  # Enhanced logging
  services.journald.extraConfig = ''
    SystemMaxUse=1G
    MaxFileSec=1week
    MaxRetentionSec=4weeks
    Compress=yes
    RateLimitInterval=30s
    RateLimitBurst=10000
    Storage=persistent
  '';

  services.logrotate = {
    enable = true;
    settings = {
      header = {
        dateext = true;
        compress = true;
        delaycompress = true;
        missingok = true;
        notifempty = true;
        create = "644 root root";
        rotate = 14;
        maxsize = "100M";
      };
      
      # Minecraft server logs rotation
      minecraft-logs = {
        files = "/var/lib/gamedata/minecraft/*/logs/*.log";
        frequency = "daily";
        rotate = 30;
        compress = true;
        delaycompress = true;
        missingok = true;
        create = "644 minecraft minecraft";
        maxsize = "500M";
        su = "minecraft minecraft";
      };
    };
  };

  # Nix optimization with better cleanup
  nix = {
    gc = {
      automatic = true;
      dates = "weekly";
      options = "--delete-older-than 7d";
      persistent = true;
    };
    settings = {
      auto-optimise-store = true;
      experimental-features = [ "nix-command" "flakes" ];
      max-jobs = "auto";
      cores = 6;  # CHANGE: adjust for your CPU core count
      sandbox = true;
      keep-outputs = false;
      keep-derivations = false;
      min-free = 1073741824;  # Keep 1GB free
      max-free = 3221225472;  # Keep max 3GB free
      
      substituters = [
        "https://cache.nixos.org"
        "https://nix-community.cachix.org"
      ];
      trusted-public-keys = [
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
      ];
    };
    optimise = {
      automatic = true;
      dates = [ "weekly" ];
    };
  };

  # System cleanup configuration
  system = {
    # Auto-upgrade with cleanup
    autoUpgrade = {
      enable = true;
      dates = "Sun 05:00";  # Weekly on Sunday at 5 AM
      allowReboot = false;
      channel = "https://nixos.org/channels/nixos-unstable";
      randomizedDelaySec = "1800";
    };
    
    # Keep only last 5 NixOS generations in bootloader
    copySystemConfiguration = false;
  };

  system.stateVersion = "25.05";
}
