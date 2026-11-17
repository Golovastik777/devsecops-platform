output "security_tools_ipv4" {
  description = "Public IPv4 of the security tooling host"
  value       = hcloud_server.security_tools.ipv4_address
}
