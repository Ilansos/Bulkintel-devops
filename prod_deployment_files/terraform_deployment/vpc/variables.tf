variable "bulkintel_vpc" {
  type = object({
    cidr_block = string
    enable_dns_support = bool
    enable_dns_hostnames = bool
    tag_name = string
    tag_terraform = string
  })
}