bulkintel_vpc = {
  cidr_block = "192.168.2.0/24"
  enable_dns_hostnames = true
  enable_dns_support = true
  tag_name = "bulkintel_vpc"
  tag_terraform = "true"
}

bulkintel_subnet = {
  cidr_block = "192.168.2.0/28"
  map_public_ip_on_launch = true
  name = "bulkintel_subnet"
  availability_zone = "il-central-1a"
  tag_terraform = "true"
}

ssh_keys = [ {
  name = "bulkintel_proxy_ssh_key"
  path = "/tmp/bulkintel_proxy.pub"
} ]

home_ip_cidr = "1.1.1.1/32"

partner_mobile_ips = "2.52.0.0/14"

ec2_instance = {
  ami = "ami-010cba0c0c7a0e510"
  instance_type = "t3.micro"
  key_name = "bulkintel_proxy_ssh_key"
  private_ip = "192.168.2.10"
  tag_name = "bulkintel_proxy"
  tag_terraform = "true"
  root_volume_size = 20
  volume_type = "gp3"
  delete_on_termination = true
  user_data_file = "./user_data.sh"
}

wg_proxy_instance_id = "i-0d15c1cb22f4e9ace"