"""Pulumi unit tests run the program against mocks: no cloud account, no state backend."""
import sys
from pathlib import Path

import pulumi

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class CloudMocks(pulumi.runtime.Mocks):
    def new_resource(self, args: pulumi.runtime.MockResourceArgs):
        outputs = dict(args.inputs)
        outputs.setdefault("arn", f"arn:aws:mock:::{args.name}")
        outputs.setdefault("name", args.inputs.get("name", args.name))
        outputs.setdefault("email", f"{args.name}@mock.iam.gserviceaccount.com")
        if args.typ == "aws:eks/cluster:Cluster":
            vpc = dict(outputs.get("vpcConfig", {}))
            vpc.setdefault("clusterSecurityGroupId", "sg-cluster")
            outputs["vpcConfig"] = vpc
        if args.typ == "aws:ec2/launchTemplate:LaunchTemplate":
            outputs.setdefault("latestVersion", 1)
        return [f"{args.name}-id", outputs]

    def call(self, args: pulumi.runtime.MockCallArgs):
        if args.token == "aws:index/getAvailabilityZones:getAvailabilityZones":
            return {"names": ["eu-central-1a", "eu-central-1b", "eu-central-1c"], "zoneIds": ["a", "b", "c"]}
        return {}


pulumi.runtime.set_mocks(CloudMocks(), preview=False)
