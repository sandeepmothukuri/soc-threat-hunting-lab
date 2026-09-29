# -*- mode: ruby -*-
# vi: set ft=ruby :
# =============================================================================
# Vagrantfile — Automated Multi-VM Build for SOC Threat Hunting Lab
# Usage:
#   vagrant up                  # Bring up all VMs together
#   vagrant up zeek-rita arkime # Bring up network sensors only
#   vagrant up velociraptor ubuntu-target # Bring up endpoint DFIR only
#   vagrant up thehive misp shuffle       # Bring up SOC management only
# =============================================================================

Vagrant.configure("2") do |config|
  # Base Box: Official Ubuntu 22.04 LTS (Jammy)
  config.vm.box = "bento/ubuntu-22.04"
  config.vm.box_check_update = false

  # Common VirtualBox configuration
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.linked_clone = true if Vagrant::VERSION >= "1.8.0"
  end

  # ===========================================================================
  # 1. Zeek + RITA Sensor VM (192.168.50.10)
  # ===========================================================================
  config.vm.define "zeek-rita" do |node|
    node.vm.hostname = "zeek-rita"
    node.vm.network "private_network", ip: "192.168.50.10", netmask: "255.255.255.0"
    node.vm.network "private_network", ip: "192.168.30.250", netmask: "255.255.255.0", nic_type: "virtio"

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-zeek-rita"
      vb.cpus = 2
      vb.memory = 4096
      vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo MONITOR_IFACE=eth2 ./01-zeek-rita/install-zeek.sh
      sudo ./01-zeek-rita/install-rita.sh
    SHELL
  end

  # ===========================================================================
  # 2. Arkime Full Packet Capture (192.168.50.20)
  # ===========================================================================
  config.vm.define "arkime" do |node|
    node.vm.hostname = "arkime"
    node.vm.network "private_network", ip: "192.168.50.20", netmask: "255.255.255.0"
    node.vm.network "private_network", ip: "192.168.30.251", netmask: "255.255.255.0", nic_type: "virtio"
    node.vm.network "forwarded_port", guest: 8005, host: 8005

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-arkime"
      vb.cpus = 4
      vb.memory = 6144
      vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo CAPTURE_IFACE=eth2 PCAP_DIR=/data/pcap ./02-arkime/install-arkime.sh
    SHELL
  end

  # ===========================================================================
  # 3. Velociraptor EDR / DFIR Server (192.168.50.30)
  # ===========================================================================
  config.vm.define "velociraptor" do |node|
    node.vm.hostname = "velociraptor"
    node.vm.network "private_network", ip: "192.168.50.30", netmask: "255.255.255.0"
    node.vm.network "forwarded_port", guest: 8889, host: 8889

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-velociraptor"
      vb.cpus = 2
      vb.memory = 4096
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo SERVER_IP=192.168.50.30 ./03-velociraptor/install-velociraptor.sh
    SHELL
  end

  # ===========================================================================
  # 4. Ubuntu Target Victim VM (192.168.30.10)
  # ===========================================================================
  config.vm.define "ubuntu-target" do |node|
    node.vm.hostname = "ubuntu-target"
    node.vm.network "private_network", ip: "192.168.30.10", netmask: "255.255.255.0"

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-ubuntu-target"
      vb.cpus = 2
      vb.memory = 2048
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo ./04-osquery/install-osquery.sh
      sudo VELOCIRAPTOR_SERVER=192.168.50.30 ./03-velociraptor/install-client.sh
    SHELL
  end

  # ===========================================================================
  # 5. MISP Threat Intelligence Platform (192.168.60.10)
  # ===========================================================================
  config.vm.define "misp" do |node|
    node.vm.hostname = "misp"
    node.vm.network "private_network", ip: "192.168.60.10", netmask: "255.255.255.0"
    node.vm.network "forwarded_port", guest: 443, host: 8443

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-misp"
      vb.cpus = 4
      vb.memory = 6144
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo MISP_IP=192.168.60.10 ./05-misp/install-misp.sh
    SHELL
  end

  # ===========================================================================
  # 6. TheHive 5 Case Management + Cortex (192.168.60.20)
  # ===========================================================================
  config.vm.define "thehive" do |node|
    node.vm.hostname = "thehive"
    node.vm.network "private_network", ip: "192.168.60.20", netmask: "255.255.255.0"
    node.vm.network "forwarded_port", guest: 9000, host: 9000
    node.vm.network "forwarded_port", guest: 9001, host: 9001

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-thehive"
      vb.cpus = 4
      vb.memory = 6144
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo HIVE_IP=192.168.60.20 ./06-thehive/install-thehive.sh
    SHELL
  end

  # ===========================================================================
  # 7. Shuffle SOAR Automation (192.168.60.30)
  # ===========================================================================
  config.vm.define "shuffle" do |node|
    node.vm.hostname = "shuffle"
    node.vm.network "private_network", ip: "192.168.60.30", netmask: "255.255.255.0"
    node.vm.network "forwarded_port", guest: 3001, host: 3001

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-shuffle"
      vb.cpus = 2
      vb.memory = 4096
    end

    node.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive
      cd /vagrant
      sudo SHUFFLE_IP=192.168.60.30 ./07-shuffle/install-shuffle.sh
    SHELL
  end

  # ===========================================================================
  # 8. Kali Linux Attacker VM (192.168.20.10)
  # ===========================================================================
  config.vm.define "kali" do |node|
    node.vm.box = "kalilinux/rolling"
    node.vm.hostname = "kali"
    node.vm.network "private_network", ip: "192.168.20.10", netmask: "255.255.255.0"

    node.vm.provider "virtualbox" do |vb|
      vb.name = "soc-kali"
      vb.cpus = 2
      vb.memory = 3072
    end
  end
end
