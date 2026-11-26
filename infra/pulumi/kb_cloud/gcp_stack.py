"""GCP: VPC with private GKE, Artifact Registry, Cloud SQL PostgreSQL on a private IP."""
from __future__ import annotations

import pulumi
import pulumi_gcp as gcp

from .settings import Settings

NODE_ROLES = ["roles/logging.logWriter", "roles/monitoring.metricWriter", "roles/monitoring.viewer",
              "roles/artifactregistry.reader"]


def build(s: Settings) -> dict:
    labels = {"project": s.name, "managed-by": "pulumi"}

    network = gcp.compute.Network(f"{s.name}-vpc", auto_create_subnetworks=False)
    subnet = gcp.compute.Subnetwork(
        f"{s.name}-subnet", network=network.id, region=s.gcp_region, ip_cidr_range="10.70.0.0/20",
        private_ip_google_access=True,
        secondary_ip_ranges=[
            gcp.compute.SubnetworkSecondaryIpRangeArgs(range_name="pods", ip_cidr_range="10.72.0.0/14"),
            gcp.compute.SubnetworkSecondaryIpRangeArgs(range_name="services", ip_cidr_range="10.76.0.0/20"),
        ],
        log_config=gcp.compute.SubnetworkLogConfigArgs(aggregation_interval="INTERVAL_5_SEC", flow_sampling=0.5,
                                                       metadata="INCLUDE_ALL_METADATA"))
    router = gcp.compute.Router(f"{s.name}-router", network=network.id, region=s.gcp_region)
    gcp.compute.RouterNat(f"{s.name}-nat", router=router.name, region=s.gcp_region,
                          nat_ip_allocate_option="AUTO_ONLY",
                          source_subnetwork_ip_ranges_to_nat="ALL_SUBNETWORKS_ALL_IP_RANGES",
                          log_config=gcp.compute.RouterNatLogConfigArgs(enable=True, filter="ERRORS_ONLY"))

    # Dedicated node identity with only the roles nodes need (not the default compute SA).
    node_sa = gcp.serviceaccount.Account(f"{s.name}-nodes", account_id=f"{s.name}-nodes",
                                         display_name=f"{s.name} GKE nodes")
    for role in NODE_ROLES:
        gcp.projects.IAMMember(f"{s.name}-nodes-{role.split('/')[-1]}", project=s.gcp_project, role=role,
                               member=node_sa.email.apply(lambda e: f"serviceAccount:{e}"))

    cluster = gcp.container.Cluster(
        f"{s.name}-gke", name=s.name, location=s.gcp_region, network=network.id, subnetwork=subnet.id,
        remove_default_node_pool=True, initial_node_count=1, deletion_protection=True,
        release_channel=gcp.container.ClusterReleaseChannelArgs(channel="REGULAR"),
        ip_allocation_policy=gcp.container.ClusterIpAllocationPolicyArgs(
            cluster_secondary_range_name="pods", services_secondary_range_name="services"),
        private_cluster_config=gcp.container.ClusterPrivateClusterConfigArgs(
            enable_private_nodes=True, enable_private_endpoint=False, master_ipv4_cidr_block="172.16.0.0/28"),
        master_authorized_networks_config=gcp.container.ClusterMasterAuthorizedNetworksConfigArgs(
            cidr_blocks=[gcp.container.ClusterMasterAuthorizedNetworksConfigCidrBlockArgs(cidr_block=c, display_name="admin")
                         for c in s.admin_cidrs]),
        workload_identity_config=gcp.container.ClusterWorkloadIdentityConfigArgs(
            workload_pool=f"{s.gcp_project}.svc.id.goog"),
        datapath_provider="ADVANCED_DATAPATH",  # Dataplane V2: enforces NetworkPolicy
        enable_shielded_nodes=True,
        resource_labels=labels)
    node_pool = gcp.container.NodePool(
        f"{s.name}-pool", cluster=cluster.id, location=s.gcp_region,
        autoscaling=gcp.container.NodePoolAutoscalingArgs(min_node_count=1, max_node_count=s.node_count_max),
        management=gcp.container.NodePoolManagementArgs(auto_repair=True, auto_upgrade=True),
        node_config=gcp.container.NodePoolNodeConfigArgs(
            machine_type="e2-standard-4", service_account=node_sa.email,
            oauth_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            workload_metadata_config=gcp.container.NodePoolNodeConfigWorkloadMetadataConfigArgs(mode="GKE_METADATA"),
            shielded_instance_config=gcp.container.NodePoolNodeConfigShieldedInstanceConfigArgs(
                enable_secure_boot=True, enable_integrity_monitoring=True),
            labels=labels))

    registry = gcp.artifactregistry.Repository(
        f"{s.name}-images", repository_id=s.name, location=s.gcp_region, format="DOCKER",
        docker_config=gcp.artifactregistry.RepositoryDockerConfigArgs(immutable_tags=True), labels=labels)

    # Cloud SQL on a private IP through private services access; no public address at all.
    peering_range = gcp.compute.GlobalAddress(f"{s.name}-sql-range", purpose="VPC_PEERING", address_type="INTERNAL",
                                              prefix_length=20, network=network.id)
    peering = gcp.servicenetworking.Connection(f"{s.name}-sql-peering", network=network.id,
                                               service="servicenetworking.googleapis.com",
                                               reserved_peering_ranges=[peering_range.name])
    db = gcp.sql.DatabaseInstance(
        f"{s.name}-db", database_version="POSTGRES_17", region=s.gcp_region, deletion_protection=True,
        settings=gcp.sql.DatabaseInstanceSettingsArgs(
            tier="db-custom-2-7680", availability_type="REGIONAL", user_labels=labels,
            ip_configuration=gcp.sql.DatabaseInstanceSettingsIpConfigurationArgs(
                ipv4_enabled=False, private_network=network.id, ssl_mode="ENCRYPTED_ONLY"),
            backup_configuration=gcp.sql.DatabaseInstanceSettingsBackupConfigurationArgs(
                enabled=True, point_in_time_recovery_enabled=True),
            database_flags=[gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(name=n, value="on")
                            for n in ("log_connections", "log_disconnections", "log_checkpoints", "log_lock_waits")],
            insights_config=gcp.sql.DatabaseInstanceSettingsInsightsConfigArgs(query_insights_enabled=True)),
        opts=pulumi.ResourceOptions(depends_on=[peering]))

    return {"network": network, "subnet": subnet, "cluster": cluster, "node_pool": node_pool,
            "node_sa": node_sa, "registry": registry, "db": db}
