# Step-by-Step Guide: Setting Up DNS-Layer Security Using Google Cloud and No-IP

## 1. DNS_server_using_BIND9.pdf

This document provides a step-by-step guide for setting up a DNS server using BIND9 on a Google Cloud VM, including firewall configuration and DNS resolution verification.

- **Step 1**: Create a free subdomain on No-IP.
- **Step 2**: Set up a Google Cloud VM named "dns-vm-instance".
- **Step 3**: Install and configure BIND9 on the VM.
- **Step 4**: Configure firewall rules on Google Cloud to allow DNS traffic.
- **Step 5**: Verify DNS functionality using `dig` command.



## 2. DNS_layer_security_Google_Cloud.pdf

This document provides a detailed summary of setting up DNS-layer security on Google Cloud, including creating a project, enabling APIs, setting up VMs, and configuring DNS.

- **Step 1**: Sign up for Google Cloud and set up billing.
- **Step 2**: Create a new project named "DNS-Layer-Security".
- **Step 3**: Enable necessary APIs (Cloud DNS API, Compute Engine API).
- **Step 4**: Create a VM instance named "dns-vm-instance".
- **Step 5**: Create a DNS zone and configure it.
- **Step 6**: Add DNS records for the VM's external IP.

## 2. CLOUD-STEP.pdf

This document provides a step-by-step guide for setting up a DNS server using BIND9 on a Google Cloud VM, including firewall configuration and DNS resolution verification.

- **Step 1**: Create a free subdomain on No-IP.
- **Step 2**: Set up a Google Cloud VM named "dns-vm-instance".
- **Step 3**: Install and configure BIND9 on the VM.
- **Step 4**: Configure firewall rules on Google Cloud to allow DNS traffic.
- **Step 5**: Verify DNS functionality using `dig` command.

## Combined Steps for Setting Up DNS-Layer Security

### Step 1: Create a Free Subdomain on No-IP

1. **Sign Up for No-IP**:
    - Go to No-IP and create a free account.
2. **Create a Free Subdomain**:
    - Create a hostname (e.g., `urldetection`) and select a free domain (e.g., `ddns.net`).

### Step 2: Set Up Google Cloud Environment

1. **Create a Google Cloud Project**:
    ```bash
    gcloud projects create dns-layer-securit
    gcloud config set project dns-layer-securit
    ```
2. **Set Up Billing**:
    - Link a billing account to your project.
3. **Enable Necessary APIs**:
    ```bash
    gcloud services enable compute.googleapis.com
    gcloud services enable container.googleapis.com
    ```

### Step 3: Create and Configure VM Instance

1. **Create VM Instance**:
    ```bash
    gcloud compute instances create dns-vm-instance --zone=us-central1-a --machine-type=e2-micro --image-family=debian-10 --image-project=debian-cloud
    ```
2. **Note the External IP Address**:
    - Example: `34.80.4.242`

### Step 4: Install and Configure BIND9 on VM

1. **SSH into Your VM**:
    ```bash
    gcloud compute ssh dns-vm-instance --zone=us-central1-a
    ```
2. **Install BIND9**:
    ```bash
    sudo apt-get update
    sudo apt-get install bind9 bind9utils bind9-doc -y
    ```
3. **Configure BIND9**:
    - Edit `/etc/bind/named.conf.local`:
      ```bash
      sudo nano /etc/bind/named.conf.local
      ```
      Add:
      ```
      zone "urldetection.ddns.net" {
          type master;
          file "/etc/bind/db.urldetection.ddns.net";
      };
      ```
    - Edit `/etc/bind/named.conf.options`:
      ```bash
      sudo nano /etc/bind/named.conf.options
      ```
      Update:
      ```
      options {
          directory "/var/cache/bind";
          forwarders {
              8.8.8.8;
              8.8.4.4;
          };
          auth-nxdomain no;
          listen-on { any; };
          listen-on-v6 { none; };
      };
      ```
    - Create and edit the zone file:
      ```bash
      sudo cp /etc/bind/db.local /etc/bind/db.urldetection.ddns.net
      sudo nano /etc/bind/db.urldetection.ddns.net
      ```
      Update:
      ```
      $TTL    604800
      @       IN      SOA     ns1.urldetection.ddns.net. admin.urldetection.ddns.net. (
                                2         ; Serial
                           604800         ; Refresh
                            86400         ; Retry
                          2419200         ; Expire
                           604800 )       ; Negative Cache TTL
      @       IN      NS      ns1.urldetection.ddns.net.
      @       IN      A       34.80.4.242
      ns1     IN      A       34.80.4.242
      www     IN      A       34.80.4.242
      ```
4. **Restart BIND9**:
    ```bash
    sudo systemctl restart bind9
    sudo systemctl enable bind9
    ```

### Step 5: Configure Firewall Rules on Google Cloud

1. **Set Up Firewall Rules**:
    ```bash
    gcloud compute firewall-rules create allow-dns --allow tcp:53,udp:53 --source-ranges 0.0.0.0/0 --target-tags=dns-server
    ```

### Step 6: Verify DNS Functionality

1. **Install `dnsutils`**:
    ```bash
    sudo apt-get install dnsutils -y
    ```
2. **Test DNS Resolution**:
    ```bash
    dig @34.80.4.242 urldetection.ddns.net
    ```

## Conclusion

These combined steps cover the setup of DNS-layer security on Google Cloud, from creating a project and VMs to configuring BIND9 and verifying DNS functionality.
