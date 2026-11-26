"""AWS: VPC with private subnets, EKS, ECR, RDS PostgreSQL, IAM, KMS."""
from __future__ import annotations

import json

import pulumi
import pulumi_aws as aws

from .settings import Settings

PUBLIC_CIDRS = ["10.60.0.0/24", "10.60.1.0/24"]
PRIVATE_CIDRS = ["10.60.10.0/24", "10.60.11.0/24"]


def _assume(service: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    })


def build(s: Settings) -> dict:
    tags = {"project": s.name, "managed-by": "pulumi"}
    zones = aws.get_availability_zones(state="available").names[:2]

    key = aws.kms.Key(f"{s.name}-kms", description=f"{s.name}: EKS secrets, ECR, RDS",
                      enable_key_rotation=True, deletion_window_in_days=30, tags=tags)

    # --- network: public subnets only for the NAT gateway and load balancers --------------
    vpc = aws.ec2.Vpc(f"{s.name}-vpc", cidr_block="10.60.0.0/16", enable_dns_hostnames=True,
                      enable_dns_support=True, tags=tags)
    igw = aws.ec2.InternetGateway(f"{s.name}-igw", vpc_id=vpc.id, tags=tags)
    public = [aws.ec2.Subnet(f"{s.name}-public-{i}", vpc_id=vpc.id, cidr_block=cidr, availability_zone=az,
                             map_public_ip_on_launch=False, tags={**tags, "kubernetes.io/role/elb": "1"})
              for i, (cidr, az) in enumerate(zip(PUBLIC_CIDRS, zones))]
    private = [aws.ec2.Subnet(f"{s.name}-private-{i}", vpc_id=vpc.id, cidr_block=cidr, availability_zone=az,
                              map_public_ip_on_launch=False, tags={**tags, "kubernetes.io/role/internal-elb": "1"})
               for i, (cidr, az) in enumerate(zip(PRIVATE_CIDRS, zones))]
    eip = aws.ec2.Eip(f"{s.name}-nat-ip", domain="vpc", tags=tags)
    nat = aws.ec2.NatGateway(f"{s.name}-nat", allocation_id=eip.id, subnet_id=public[0].id, tags=tags)
    public_rt = aws.ec2.RouteTable(f"{s.name}-public-rt", vpc_id=vpc.id, tags=tags,
                                   routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)])
    private_rt = aws.ec2.RouteTable(f"{s.name}-private-rt", vpc_id=vpc.id, tags=tags,
                                    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", nat_gateway_id=nat.id)])
    for i, subnet in enumerate(public):
        aws.ec2.RouteTableAssociation(f"{s.name}-public-rta-{i}", subnet_id=subnet.id, route_table_id=public_rt.id)
    for i, subnet in enumerate(private):
        aws.ec2.RouteTableAssociation(f"{s.name}-private-rta-{i}", subnet_id=subnet.id, route_table_id=private_rt.id)

    flow_log_group = aws.cloudwatch.LogGroup(f"{s.name}-vpc-flow-logs", retention_in_days=90,
                                             kms_key_id=key.arn, tags=tags)
    flow_role = aws.iam.Role(f"{s.name}-flow-logs", assume_role_policy=_assume("vpc-flow-logs.amazonaws.com"), tags=tags)
    aws.iam.RolePolicy(f"{s.name}-flow-logs", role=flow_role.id, policy=flow_log_group.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Resource": f"{arn}:*",
                       "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]}],
    })))
    aws.ec2.FlowLog(f"{s.name}-vpc-flow-log", vpc_id=vpc.id, traffic_type="ALL", log_destination_type="cloud-watch-logs",
                    log_destination=flow_log_group.arn, iam_role_arn=flow_role.arn, tags=tags)

    # --- container registry ----------------------------------------------------------------
    ecr = aws.ecr.Repository(
        f"{s.name}-ecr", name=s.name, image_tag_mutability="IMMUTABLE",
        image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(scan_on_push=True),
        encryption_configurations=[aws.ecr.RepositoryEncryptionConfigurationArgs(encryption_type="KMS", kms_key=key.arn)],
        tags=tags)
    aws.ecr.LifecyclePolicy(f"{s.name}-ecr-lifecycle", repository=ecr.name, policy=json.dumps({"rules": [{
        "rulePriority": 1, "description": "Keep the last 30 images",
        "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 30},
        "action": {"type": "expire"}}]}))

    # --- EKS --------------------------------------------------------------------------------
    cluster_role = aws.iam.Role(f"{s.name}-eks-cluster", assume_role_policy=_assume("eks.amazonaws.com"), tags=tags)
    aws.iam.RolePolicyAttachment(f"{s.name}-eks-cluster-policy", role=cluster_role.name,
                                 policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    cluster = aws.eks.Cluster(
        f"{s.name}-eks", name=s.name, role_arn=cluster_role.arn, version=s.kubernetes_version,
        vpc_config=aws.eks.ClusterVpcConfigArgs(
            subnet_ids=[sn.id for sn in private], endpoint_private_access=True,
            endpoint_public_access=True, public_access_cidrs=s.admin_cidrs),
        encryption_config=aws.eks.ClusterEncryptionConfigArgs(
            provider=aws.eks.ClusterEncryptionConfigProviderArgs(key_arn=key.arn), resources=["secrets"]),
        enabled_cluster_log_types=["api", "audit", "authenticator"],
        access_config=aws.eks.ClusterAccessConfigArgs(authentication_mode="API"),
        tags=tags)

    node_role = aws.iam.Role(f"{s.name}-eks-nodes", assume_role_policy=_assume("ec2.amazonaws.com"), tags=tags)
    for policy in ("AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"):
        aws.iam.RolePolicyAttachment(f"{s.name}-nodes-{policy}", role=node_role.name,
                                     policy_arn=f"arn:aws:iam::aws:policy/{policy}")
    launch_template = aws.ec2.LaunchTemplate(
        f"{s.name}-nodes-lt",
        # IMDSv2 only, one hop: pods cannot read the node's instance credentials.
        metadata_options=aws.ec2.LaunchTemplateMetadataOptionsArgs(
            http_endpoint="enabled", http_tokens="required", http_put_response_hop_limit=1),
        block_device_mappings=[aws.ec2.LaunchTemplateBlockDeviceMappingArgs(
            device_name="/dev/xvda",
            ebs=aws.ec2.LaunchTemplateBlockDeviceMappingEbsArgs(volume_size=50, encrypted="true", kms_key_id=key.arn))],
        tags=tags)
    node_group = aws.eks.NodeGroup(
        f"{s.name}-nodes", cluster_name=cluster.name, node_role_arn=node_role.arn,
        subnet_ids=[sn.id for sn in private], instance_types=["t3.large"],
        scaling_config=aws.eks.NodeGroupScalingConfigArgs(
            desired_size=s.node_count_min, min_size=s.node_count_min, max_size=s.node_count_max),
        launch_template=aws.eks.NodeGroupLaunchTemplateArgs(id=launch_template.id, version=launch_template.latest_version),
        tags=tags)

    # --- RDS PostgreSQL: private, encrypted, password managed by Secrets Manager -------------
    db_subnets = aws.rds.SubnetGroup(f"{s.name}-db-subnets", subnet_ids=[sn.id for sn in private], tags=tags)
    db_sg = aws.ec2.SecurityGroup(
        f"{s.name}-db", vpc_id=vpc.id, description="PostgreSQL from the EKS cluster only",
        ingress=[aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp", from_port=5432, to_port=5432, description="EKS cluster",
            security_groups=[cluster.vpc_config.cluster_security_group_id])],
        tags=tags)
    db = aws.rds.Instance(
        f"{s.name}-db", engine="postgres", engine_version="17", instance_class="db.t4g.medium",
        allocated_storage=50, max_allocated_storage=200, storage_type="gp3",
        storage_encrypted=True, kms_key_id=key.arn,
        username="kb_admin", manage_master_user_password=True,
        db_subnet_group_name=db_subnets.name, vpc_security_group_ids=[db_sg.id],
        publicly_accessible=False, multi_az=True, deletion_protection=True,
        backup_retention_period=7, copy_tags_to_snapshot=True,
        skip_final_snapshot=False, final_snapshot_identifier=f"{s.name}-db-final",
        iam_database_authentication_enabled=True, auto_minor_version_upgrade=True,
        performance_insights_enabled=True, performance_insights_kms_key_id=key.arn,
        enabled_cloudwatch_logs_exports=["postgresql"],
        tags=tags)

    return {"vpc": vpc, "public": public, "private": private, "key": key, "ecr": ecr, "cluster": cluster,
            "node_group": node_group, "launch_template": launch_template, "db": db, "db_sg": db_sg}
