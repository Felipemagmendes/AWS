# LISTA TODOS OS RECURSOS DA AWS




import boto3
import csv

ec2_client = boto3.client(
    'ec2'
)
s3_client = boto3.client(
    's3'
)

rds_client = boto3.client(
    'rds'
)
route53_client = boto3.client(
    'route53'
)
lambda_client = boto3.client(
    'lambda'
)

route53 = boto3.client(
    'route53'
)

iam_client = boto3.client(
    'iam'
)
elb_client = boto3.client(
    'elbv2'
)
acm_client = boto3.client(
    'acm'
)
network_firewall = boto3.client(
    'network-firewall'
)

ecs = boto3.client(
    'ecs'
)

waf = boto3.client(
    'wafv2'
)

ga = boto3.client(
    'globalaccelerator'
)


def list_ec2_instances():
    instances = ec2_client.describe_instances()
    instance_data = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_data.append({
                    'InstanceId': instance.get('InstanceId'),
                    'State': instance['State']['Name'], 
                    'InstanceType': instance.get('InstanceType'),
                    'PrivateIP': instance.get('PrivateIpAddress'),
                    'PublicIP': instance.get('PublicIpAddress'),
                    'KeyName': instance.get('KeyName'),
                    'SubnetId': instance.get('SubnetId'),
                    'VpcId': instance.get('VpcId'),
                    'ImageId': instance.get('ImageId'),
                    'LaunchTime': instance.get('LaunchTime').isoformat(),
                    'Architecture': instance.get('Architecture'),
                    'Platform': instance.get('Platform', 'Linux/Unix'),
                    #'Tags': instance.get('Tags', []),
                    'SecurityGroups' : instance.get('SecurityGroups'),
                    'Zona': instance.get('AvailabilityZone'),
                    'DNSName' : instance.get('PublicDnsName')
                
            })
    return instance_data

def list_s3_buckets():
    buckets = s3_client.list_buckets()
    bucket_data = [{'BucketName': bucket['Name'], 'CreationDate': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')} for bucket in buckets['Buckets']]
    return bucket_data

def list_iam_users():
    users = iam_client.list_users()
    user_data = [{'UserName': user['UserName'], 'UserId': user['UserId'], 'CreateDate': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')} for user in users['Users']]
    return user_data

def list_route53_hosted_zones():
    zones = route53_client.list_hosted_zones()
    zone_data = [{'Name': zone['Name'], 'Id': zone['Id'], 'ResourceRecordSetCount': zone['ResourceRecordSetCount']} for zone in zones['HostedZones']]
    return zone_data

def list_network_security_groups():
    security_groups = ec2_client.describe_security_groups()
    sg_data = [{'GroupName': sg['GroupName'], 'GroupId': sg['GroupId'], 'Description': sg['Description']} for sg in security_groups['SecurityGroups']]
    return sg_data

def list_load_balancers():
    load_balancers = elb_client.describe_load_balancers()
    lb_data = [{'LoadBalancerName': lb['LoadBalancerName'], 'DNSName': lb['DNSName'], 'State': lb['State']['Code']} for lb in load_balancers['LoadBalancers']]
    return lb_data

def list_snapshots():
    snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])
    snapshot_data = [{'SnapshotId': snap['SnapshotId'], 'VolumeId': snap['VolumeId'], 'StartTime': snap['StartTime'].strftime('%Y-%m-%d %H:%M:%S')} for snap in snapshots['Snapshots']]
    return snapshot_data

def list_volumes():
    volumes = ec2_client.describe_volumes()
    volume_data = [{'VolumeId': vol['VolumeId'], 'Size': vol['Size'], 'State': vol['State']} for vol in volumes['Volumes']]
    return volume_data

def list_certificates():
    certificates = acm_client.list_certificates()
    cert_data = [{'CertificateArn': cert['CertificateArn'], 'DomainName': cert['DomainName']} for cert in certificates['CertificateSummaryList']]
    return cert_data

def list_vpcs():
    vpcs = ec2_client.describe_vpcs()
    vpc_data = [{'VpcId': vpc['VpcId'], 'State': vpc['State'], 'CidrBlock': vpc['CidrBlock']} for vpc in vpcs['Vpcs']]
    return vpc_data

def list_nat_gateways():
    nat_gateways = ec2_client.describe_nat_gateways()
    nat_data = [{'NatGatewayId': nat['NatGatewayId'], 'State': nat['State'], 'VpcId': nat['VpcId']} for nat in nat_gateways['NatGateways']]
    return nat_data

def list_network_acls():
    acls = ec2_client.describe_network_acls()
    acl_data = [{'NetworkAclId': acl['NetworkAclId'], 'VpcId': acl['VpcId']} for acl in acls['NetworkAcls']]
    return acl_data

def list_firewall_policies():
    policies = network_firewall.list_firewall_policies()
    policy_data = [{'Name': policy['Name'], 'Arn': policy['Arn']} for policy in policies['FirewallPolicies']]
    return policy_data

def list_site_to_site_vpn():
    vpn_connections = ec2_client.describe_vpn_connections()
    vpn_data = [{'VpnConnectionId': vpn['VpnConnectionId'], 'State': vpn['State'], 'VpcId': vpn['VpcId']} for vpn in vpn_connections['VpnConnections']]
    return vpn_data

def list_containers():
    clusters = ecs.list_clusters()['clusterArns']
    container_data = []
    for cluster in clusters:
        tasks = ecs.list_tasks(cluster=cluster)['taskArns']
        for task in tasks:
            task_details = ecs.describe_tasks(cluster=cluster, tasks=[task])['tasks']
            for detail in task_details:
                container_data.append({
                    'Cluster': cluster,
                    'TaskArn': task,
                    'LastStatus': detail['lastStatus'],
                    'DesiredStatus': detail['desiredStatus']
                })
    return container_data

def list_waf_rules():
    rules = waf.list_web_acls(Scope='REGIONAL')['WebACLs']
    waf_data = [{'Name': rule['Name'], 'Id': rule['Id'], 'ARN': rule['ARN']} for rule in rules]
    return waf_data

"""
EM TESTE AINDA

def list_global_accelerators():
    accelerators = ga.list_accelerators()['Accelerators']
    ga_data = [{'Name': acc['Name'], 'AcceleratorArn': acc['AcceleratorArn'], 'Status': acc['Status']} for acc in accelerators]
    return ga_data

"""

def list_key_pairs():
    key_pairs = ec2_client.describe_key_pairs()
    key_data = [{'KeyName': kp['KeyName'], 'KeyPairId': kp['KeyPairId']} for kp in key_pairs['KeyPairs']]
    return key_data

def list_vpc_peering_connections():
    peerings = ec2_client.describe_vpc_peering_connections()
    peering_data = [{'VpcPeeringConnectionId': p['VpcPeeringConnectionId'], 'Status': p['Status']['Code']} for p in peerings['VpcPeeringConnections']]
    return peering_data

def write_to_csv(data, filename):
    """Writes a list of dictionaries to a CSV file."""
    if not data:
        print(f"No data to write for {filename}")
        return

    keys = data[0].keys()
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

if __name__ == '__main__':
    all_data = {
        'ec2_instances.csv': list_ec2_instances(),
        's3_buckets.csv': list_s3_buckets(),
        'iam_users.csv': list_iam_users(),
        'route53_zones.csv': list_route53_hosted_zones(),
        'network_security_groups.csv': list_network_security_groups(),
        'load_balancers.csv': list_load_balancers(),
        'snapshots.csv': list_snapshots(),
        'volumes.csv': list_volumes(),
        'certificates.csv': list_certificates(),
        'vpcs.csv': list_vpcs(),
        'nat_gateways.csv': list_nat_gateways(),
        'network_acls.csv': list_network_acls(),
        'firewall_policies.csv': list_firewall_policies(),
        'site_to_site_vpn.csv': list_site_to_site_vpn(),
        'cointainers.csv': list_containers(),
        'waf_rules.csv': list_waf_rules(),
        #'global_acelerator.csv': list_global_accelerators(),
        'key_pair.csv': list_key_pairs(),
        'vpc_peering.csv': list_vpc_peering_connections()
    }

    for filename, data in all_data.items():
        write_to_csv(data, filename)
        print(f"Data written to {filename}")
