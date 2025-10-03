output "allow_ssh_and_ping_sg_id" {
  value = aws_security_group.allow_ssh_ping.id
}

output "allow_bulkintel_sg_id" {
  value = aws_security_group.allow_bulkintel_from_partner_ips.id
}