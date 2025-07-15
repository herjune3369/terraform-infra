output "web1_public_ip" {
  value = aws_instance.web1.public_ip
}

output "web2_public_ip" {
  value = aws_instance.web2.public_ip
}


output "alb_dns_name" {
  value = aws_lb.app_lb.dns_name
}

output "rds_endpoint" {
  value = aws_db_instance.flask_db.address
}

output "rds_database" {
  value = aws_db_instance.flask_db.db_name
}

# EKS 클러스터 출력
output "eks_cluster_name" {
  value = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "eks_cluster_arn" {
  value = aws_eks_cluster.main.arn
}

output "eks_cluster_version" {
  value = aws_eks_cluster.main.version
}

output "eks_node_group_name" {
  value = aws_eks_node_group.main.node_group_name
}
