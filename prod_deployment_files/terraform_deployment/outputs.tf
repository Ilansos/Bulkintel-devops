output "bulkintel_proxy_eip" {
  description = "Public Elastic IP (from ec2 module)"
  value       = module.ec2_instance.bulkintel_proxy_eip
}