variable "bulkintel_vpc" {
  type = object({
    cidr_block = string
    enable_dns_support = bool
    enable_dns_hostnames = bool
    tag_name = string
    tag_terraform = string
  })
}

variable "bulkintel_subnet" {
    type = object({
      cidr_block = string
      map_public_ip_on_launch = bool
      name = string
      availability_zone = string
      tag_terraform = string
    })
}

variable "ssh_keys" {
  description = "List of ssh key names and local paths of the SSH keys you want to upload to AWS"
  type = list(object({
    name = string
    path = string
  }))
}

variable "home_ip_cidr" {
  type = string
}

variable "partner_mobile_ips" {
  type = string
}

variable "ec2_instance" {
  type = object({
    ami                     = string
    instance_type           = string
    key_name                = string
    private_ip              = string
    tag_name                = string
    tag_terraform           = string
    root_volume_size        = number
    volume_type             = string
    delete_on_termination   = bool
    user_data_file          = string
  })
}

variable "wg_proxy_instance_id" {
  type = string
}