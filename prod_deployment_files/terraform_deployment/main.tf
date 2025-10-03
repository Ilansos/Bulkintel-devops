module "vpc" {
  source = "./vpc"
  bulkintel_vpc = {
    cidr_block = var.bulkintel_vpc.cidr_block
    enable_dns_support = var.bulkintel_vpc.enable_dns_support
    enable_dns_hostnames = var.bulkintel_vpc.enable_dns_hostnames
    tag_name = var.bulkintel_vpc.tag_name
    tag_terraform = var.bulkintel_vpc.tag_terraform
  }
}

module "subnet" {
  source = "./subnet"
  bulkintel_subnet = {
    vpc_id = module.vpc.bulkintel_vpc_id
    cidr_block = var.bulkintel_subnet.cidr_block
    map_public_ip_on_launch = var.bulkintel_subnet.map_public_ip_on_launch
    name = var.bulkintel_subnet.name
    availability_zone = var.bulkintel_subnet.availability_zone
    tag_terraform = var.bulkintel_subnet.tag_terraform
  }
}

module "ssh_keys" {
  source = "./ssh_keys"
  ssh_keys = var.ssh_keys
}

module "security_groups" {
  source = "./security_group"
  vpc_id = module.vpc.bulkintel_vpc_id
  home_ip_cidr = var.home_ip_cidr
  partner_mobile_ips = var.partner_mobile_ips
}

module "ec2_instance" {
  source = "./ec2"
  ec2_instance = {
    ami = var.ec2_instance.ami
    instance_type = var.ec2_instance.instance_type
    key_name = var.ec2_instance.key_name
    vpc_security_group_ids = [module.security_groups.allow_ssh_and_ping_sg_id, module.security_groups.allow_bulkintel_sg_id]
    subnet_id = module.subnet.bulkintel_subnet_id
    private_ip = var.ec2_instance.private_ip
    tag_name = var.ec2_instance.tag_name
    tag_terraform = var.ec2_instance.tag_terraform
    root_volume_size = var.ec2_instance.root_volume_size
    volume_type = var.ec2_instance.volume_type
    delete_on_termination = var.ec2_instance.delete_on_termination
    user_data_file = var.ec2_instance.user_data_file
  }
}

module "update_wg_proxy_sg" {
  source = "./update_wg_proxy_sg"
  wg_proxy_instance_id = var.wg_proxy_instance_id
  bulkintel_proxy_eip = module.ec2_instance.bulkintel_proxy_eip
}