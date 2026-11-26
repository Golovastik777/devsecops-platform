"""Entry point: `pulumi up -s aws-prod` or `pulumi up -s gcp-prod`."""
import pulumi

from kb_cloud.settings import Settings

config = pulumi.Config()
cloud = config.require("cloud")
settings = Settings(admin_cidrs=config.require_object("adminCidrs"))

if cloud == "aws":
    from kb_cloud import aws_stack

    r = aws_stack.build(settings)
    pulumi.export("cluster_name", r["cluster"].name)
    pulumi.export("registry_url", r["ecr"].repository_url)
    pulumi.export("db_endpoint", r["db"].endpoint)
elif cloud == "gcp":
    from kb_cloud import gcp_stack

    gcp_config = pulumi.Config("gcp")
    settings = Settings(admin_cidrs=settings.admin_cidrs, gcp_project=gcp_config.require("project"),
                        gcp_region=gcp_config.require("region"))
    r = gcp_stack.build(settings)
    pulumi.export("cluster_name", r["cluster"].name)
    pulumi.export("registry", r["registry"].id)
    pulumi.export("db_connection_name", r["db"].connection_name)
else:
    raise ValueError(f"unknown cloud {cloud!r}: expected aws or gcp")
