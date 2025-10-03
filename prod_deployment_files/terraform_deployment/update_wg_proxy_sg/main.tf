locals {
  source_cidr = "${var.bulkintel_proxy_eip}/32"
}

# Look up the target instance
data "aws_instance" "wg_proxy" {
  instance_id = var.wg_proxy_instance_id
}

# Get VPC via the instance's subnet
data "aws_subnet" "wg_proxy_subnet" {
  id = data.aws_instance.wg_proxy.subnet_id
}

# Find the primary ENI (device-index = 0) of the instance
data "aws_network_interfaces" "wg_primary" {
  filter {
    name   = "attachment.instance-id"
    values = [data.aws_instance.wg_proxy.id]
  }
  filter {
    name   = "attachment.device-index"
    values = ["0"]
  }
}

resource "aws_security_group" "allow_bulkintel_proxy_to_wg" {
  name = "allow_bulkintel_proxy_to_wg"
  description = "Allow BulkIntel Proxy to WireGuard Server"
  vpc_id      = data.aws_subnet.wg_proxy_subnet.vpc_id

  ingress {
    from_port = "51820"
    to_port = "51820"
    protocol = "udp"
    cidr_blocks = [local.source_cidr]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Attach the new SG to the instance's primary ENI (keeps existing SGs)
resource "aws_network_interface_sg_attachment" "wg_attach" {
  security_group_id    = aws_security_group.allow_bulkintel_proxy_to_wg.id
  network_interface_id = data.aws_network_interfaces.wg_primary.ids[0]
}