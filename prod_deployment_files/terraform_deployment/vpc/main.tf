resource "aws_vpc" "bulkintel_vpc" {
  cidr_block = var.bulkintel_vpc.cidr_block
  enable_dns_support = var.bulkintel_vpc.enable_dns_support
  enable_dns_hostnames = var.bulkintel_vpc.enable_dns_hostnames

  tags = {
    Name = var.bulkintel_vpc.tag_name
    Terraform = var.bulkintel_vpc.tag_terraform
  }
}