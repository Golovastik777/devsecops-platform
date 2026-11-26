import pulumi
import pytest

from kb_cloud import aws_stack
from kb_cloud.settings import Settings

R = aws_stack.build(Settings(admin_cidrs=["198.51.100.0/24"]))


@pulumi.runtime.test
def test_eks_api_is_private_or_allowlisted_and_secrets_encrypted():
    def check(args):
        vpc, enc, logs = args
        assert vpc["endpoint_private_access"] is True
        assert "0.0.0.0/0" not in vpc["public_access_cidrs"]
        assert enc["resources"] == ["secrets"]
        assert {"api", "audit"} <= set(logs)
    c = R["cluster"]
    return pulumi.Output.all(c.vpc_config, c.encryption_config, c.enabled_cluster_log_types).apply(check)


@pulumi.runtime.test
def test_nodes_run_in_private_subnets_with_imdsv2():
    def check(args):
        node_subnets, private_ids, metadata = args
        assert sorted(node_subnets) == sorted(private_ids)
        assert metadata["http_tokens"] == "required" and metadata["http_put_response_hop_limit"] == 1
    ids = pulumi.Output.all(*[s.id for s in R["private"]])
    return pulumi.Output.all(R["node_group"].subnet_ids, ids, R["launch_template"].metadata_options).apply(check)


@pulumi.runtime.test
def test_ecr_is_immutable_scanned_and_kms_encrypted():
    def check(args):
        mutability, scan, enc = args
        assert mutability == "IMMUTABLE"
        assert scan["scan_on_push"] is True
        assert enc[0]["encryption_type"] == "KMS"
    e = R["ecr"]
    return pulumi.Output.all(e.image_tag_mutability, e.image_scanning_configuration, e.encryption_configurations).apply(check)


@pulumi.runtime.test
def test_rds_is_private_encrypted_and_has_no_password_in_code():
    def check(args):
        public, encrypted, multi_az, deletion, managed, password, backups = args
        assert public is False and encrypted is True and multi_az is True and deletion is True
        assert managed is True and not password  # master password lives in Secrets Manager
        assert backups >= 7
    d = R["db"]
    return pulumi.Output.all(d.publicly_accessible, d.storage_encrypted, d.multi_az, d.deletion_protection,
                             d.manage_master_user_password, d.password, d.backup_retention_period).apply(check)


@pulumi.runtime.test
def test_database_accepts_only_the_cluster_security_group():
    def check(ingress):
        assert len(ingress) == 1
        rule = ingress[0]
        assert rule["from_port"] == rule["to_port"] == 5432
        assert not rule.get("cidr_blocks")
        assert rule["security_groups"] == ["sg-cluster"]
    return R["db_sg"].ingress.apply(check)


@pulumi.runtime.test
def test_subnets_never_assign_public_ips():
    def check(flags):
        assert not any(flags)
    return pulumi.Output.all(*[s.map_public_ip_on_launch for s in R["public"] + R["private"]]).apply(check)


def test_open_admin_cidr_is_rejected():
    with pytest.raises(ValueError):
        Settings(admin_cidrs=["0.0.0.0/0"])
