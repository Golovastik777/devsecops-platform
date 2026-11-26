import pulumi

from kb_cloud import gcp_stack
from kb_cloud.settings import Settings

R = gcp_stack.build(Settings(admin_cidrs=["198.51.100.0/24"], gcp_project="test-project"))


@pulumi.runtime.test
def test_gke_is_private_with_authorized_networks_and_workload_identity():
    def check(args):
        private, authorized, wi, datapath, shielded = args
        assert private["enable_private_nodes"] is True
        assert [b["cidr_block"] for b in authorized["cidr_blocks"]] == ["198.51.100.0/24"]
        assert wi["workload_pool"] == "test-project.svc.id.goog"
        assert datapath == "ADVANCED_DATAPATH"  # NetworkPolicy enforcement
        assert shielded is True
    c = R["cluster"]
    return pulumi.Output.all(c.private_cluster_config, c.master_authorized_networks_config,
                             c.workload_identity_config, c.datapath_provider, c.enable_shielded_nodes).apply(check)


@pulumi.runtime.test
def test_nodes_use_dedicated_service_account_and_gke_metadata():
    def check(args):
        node_config, sa_email = args
        assert node_config["service_account"] == sa_email
        assert node_config["workload_metadata_config"]["mode"] == "GKE_METADATA"
        assert node_config["shielded_instance_config"]["enable_secure_boot"] is True
    return pulumi.Output.all(R["node_pool"].node_config, R["node_sa"].email).apply(check)


@pulumi.runtime.test
def test_cloud_sql_has_no_public_ip_and_requires_tls():
    def check(settings):
        ip = settings["ip_configuration"]
        assert ip["ipv4_enabled"] is False and ip["ssl_mode"] == "ENCRYPTED_ONLY"
        assert settings["availability_type"] == "REGIONAL"
        assert settings["backup_configuration"]["point_in_time_recovery_enabled"] is True
    return R["db"].settings.apply(check)


@pulumi.runtime.test
def test_registry_tags_are_immutable():
    return R["registry"].docker_config.apply(lambda cfg: _assert(cfg["immutable_tags"] is True))


def _assert(condition):
    assert condition
