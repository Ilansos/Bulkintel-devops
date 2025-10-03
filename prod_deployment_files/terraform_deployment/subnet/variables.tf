variable "bulkintel_subnet" {
    type = object({
      vpc_id = string
      cidr_block = string
      map_public_ip_on_launch = bool
      name = string
      availability_zone = string
      tag_terraform = string
    })
}