variable "ec2_instance" {
  type = object({
    ami                     = string
    instance_type           = string
    key_name                = string
    vpc_security_group_ids  = list(string)
    subnet_id               = string
    private_ip              = string
    tag_name                = string
    tag_terraform           = string
    root_volume_size        = number
    volume_type             = string
    delete_on_termination   = bool
    user_data_file          = string
  })
}