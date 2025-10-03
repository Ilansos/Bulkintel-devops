resource "aws_eip" "elastic_ip_bulkintel_proxy" {
  domain = "vpc"
  instance = aws_instance.bulkintel_proxy_ec2.id
  tags = {
    Name = "Elastic_IP_for_Bulkintel_Proxy"
  }
}

resource "aws_instance" "bulkintel_proxy_ec2" {
  ami                     = var.ec2_instance.ami
  instance_type           = var.ec2_instance.instance_type
  key_name                = var.ec2_instance.key_name
  vpc_security_group_ids  = var.ec2_instance.vpc_security_group_ids
  subnet_id               = var.ec2_instance.subnet_id
  private_ip              = var.ec2_instance.private_ip

  root_block_device {
    volume_size           = var.ec2_instance.root_volume_size
    volume_type           = var.ec2_instance.volume_type
    delete_on_termination = var.ec2_instance.delete_on_termination
  }

  user_data = file(var.ec2_instance.user_data_file)

  tags = {
    Name = var.ec2_instance.tag_name
    Terraform = var.ec2_instance.tag_terraform
  }
}
