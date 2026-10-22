output "alb_arn" {
  value = aws_lb.this.arn
}

output "alb_arn_suffix" {
  value = aws_lb.this.arn_suffix
}

output "alb_dns_name" {
  description = "Point <domain_name> and <mailview_domain_name> CNAME/ALIAS here (DNS is not managed by this stack)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "web_target_group_arn" {
  value = aws_lb_target_group.web.arn
}

output "mailview_target_group_arn" {
  value = aws_lb_target_group.mailview.arn
}

output "web_acl_name" {
  value = aws_wafv2_web_acl.this.name
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}
