# outputs.tf
output "bulkintel_proxy_eip" {
    description = "Public Elastic IP for the BulkIntel proxy"
    value       = aws_eip.elastic_ip_bulkintel_proxy.public_ip
}