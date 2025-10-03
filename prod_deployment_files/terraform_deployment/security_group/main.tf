resource "aws_security_group" "allow_ssh_ping" {
  name = "allow_ssh_and_ping_from_home_ip"
  description = "Allow SSH and Ping from Home IP"
  vpc_id = var.vpc_id

  ingress {
    from_port = "22"
    to_port = "22"
    protocol = "tcp"
    cidr_blocks = [var.home_ip_cidr]
  }

  ingress {
    from_port = -1
    to_port = -1
    protocol = "ICMP"
    cidr_blocks = [var.home_ip_cidr]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "allow_bulkintel_from_partner_ips" {
  name = "allow_bulkintel_from_partner_ips"
  description = "Allow Port 80 and 443 from Partner Mobile IPs CIDR"
  vpc_id = var.vpc_id

  ingress {
    from_port = "80"
    to_port = "80"
    protocol = "tcp"
    cidr_blocks = [var.partner_mobile_ips]
  }

  ingress {
    from_port = "443"
    to_port = "443"
    protocol = "tcp"
    cidr_blocks = [var.partner_mobile_ips]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}