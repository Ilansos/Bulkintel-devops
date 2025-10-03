# WireGuard Proxy IAC Deployment

This project was created to set up a reverse proxy in AWS for WireGuard VPN of Home.Lab

## How was deployed:

- First we create a VPC with subnet: "192.168.1.0/24"
- Second we set up a small public subnet: "192.168.1.0/28"
- Third we uploaded an ssh key for the EC2: "wg_proxy_ssh_key"
- Fourth we set up 2 security groups:
    - The first allows ICMP and SSH connections from Home IP 
    - The second allows connections to UDP port 51820
- Fifth we deployed an EC2 machine with the following parameters:
    - OS: Ubuntu 22.04
    - Type: T3.Micro
    - Root Volume: 20GB
    - Private IP: "192.168.1.10"
    - Elastic IP asociated
- Sixth we set up NGINX as a reverse proxy:
    - It was configured via user data script
    - It listens on port UDP 51820 and forwards the traffic to WireGuard port 51820 on Home.Lab