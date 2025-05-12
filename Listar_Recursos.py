# Lista Subnets, WAF, Instancias, e Load Balancer


import boto3
import csv
import json
from datetime import datetime

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


def list_subnets_and_resources():
    # Get subnets
    subnets = ec2_client.describe_subnets()['Subnets']
    subnet_data = {}

    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        subnet_data[subnet_id] = {
            'Resources': []
        }

    # Get EC2 instances
    instances = ec2_client.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            subnet_id = instance['SubnetId']
            resource_info = {
                'Type': 'EC2',
                'InstanceId': instance['InstanceId'],
                'State': instance['State']['Name'],
                'Tags': instance.get('Tags', []),
                'SubnetId': subnet_id,
                'PrivateIpAddress': instance.get('PrivateIpAddress'),
                'PublicIpAddress': instance.get('PublicIpAddress'),
                'SecurityGroups': instance.get('SecurityGroups', []),
                'Volumes': instance.get('BlockDeviceMappings', [])
            }
            subnet_data[subnet_id]['Resources'].append(resource_info)

    # Get RDS instances
    rds_instances = rds_client.describe_db_instances()['DBInstances']
    for db_instance in rds_instances:
        subnet_group = db_instance['DBSubnetGroup']['Subnets']
        for subnet in subnet_group:
            subnet_id = subnet['SubnetIdentifier']
            resource_info = {
                'Type': 'RDS',
                'DBInstanceIdentifier': db_instance['DBInstanceIdentifier'],
                'Engine': db_instance['Engine'],
                'SubnetId': subnet_id
            }
            if subnet_id in subnet_data:
                subnet_data[subnet_id]['Resources'].append(resource_info)

    # Get S3 buckets (Note: S3 is global and not tied to subnets, but we include for completeness)
    buckets = s3_client.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        bucket_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        bucket_policy = None
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
        except Exception:
            pass  # Bucket policy might not exist

        subnet_data['global'] = subnet_data.get('global', {'Resources': []})
        subnet_data['global']['Resources'].append({
            'Type': 'S3',
            'BucketName': bucket_name,
            'ACL': bucket_acl,
            'Policy': bucket_policy
        })

    return subnet_data

def list_waf_associations():
    # Get WAF Web ACLs
    waf_data = []
    web_acls = waf.list_web_acls(Scope='REGIONAL')['WebACLs']

    for acl in web_acls:
        acl_name = acl['Name']
        acl_id = acl['Id']
        resources = waf.list_resources_for_web_acl(WebACLArn=acl['ARN'])['ResourceArns']
        waf_data.append({
            'WAF Name': acl_name,
            'WAF ID': acl_id,
            'Associated Resources': resources
        })

    return waf_data

def list_load_balancers():
    # Get Load Balancers
    lb_data = []
    load_balancers = elb_client.describe_load_balancers()['LoadBalancers']

    for lb in load_balancers:
        lb_data.append({
            'LoadBalancerName': lb['LoadBalancerName'],
            'LoadBalancerArn': lb['LoadBalancerArn'],
            'Type': lb['Type'],
            'Scheme': lb['Scheme'],
            'DNSName': lb.get('DNSName'),
            'VpcId': lb.get('VpcId'),
            'State': lb['State']['Code']
        })

    return lb_data

def serialize_object(obj):
    """Convert non-serializable objects (e.g., datetime) to strings."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def export_subnets_to_csv(subnet_resources, filename='subnets_Saude.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Subnet ID", "Resource Type", "Details"])

        for subnet_id, data in subnet_resources.items():
            for resource in data['Resources']:
                writer.writerow([
                    subnet_id,
                    resource['Type'],
                    json.dumps(resource, default=serialize_object)  # Convert resource details to JSON string
                ])

def export_waf_to_csv(waf_data, filename='waf_associations_Saude.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["WAF Name", "WAF ID", "Associated Resources"])

        for acl in waf_data:
            writer.writerow([
                acl['WAF Name'],
                acl['WAF ID'],
                json.dumps(acl['Associated Resources'], default=serialize_object)
            ])

def export_instances_to_csv(instances, filename='instances_Saude.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Instance ID", "State", "Subnet ID", "Private IP", "Public IP", "Security Groups", "Volumes", "Tags"])

        for instance in instances:
            writer.writerow([
                instance['InstanceId'],
                instance['State'],
                instance['SubnetId'],
                instance.get('PrivateIpAddress', 'N/A'),
                instance.get('PublicIpAddress', 'N/A'),
                json.dumps(instance.get('SecurityGroups', []), default=serialize_object),
                json.dumps(instance.get('Volumes', []), default=serialize_object),
                json.dumps(instance.get('Tags', []), default=serialize_object)
            ])

def export_load_balancers_to_csv(lb_data, filename='load_balancers_Saude.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Load Balancer Name", "ARN", "Type", "Scheme", "DNS Name", "VPC ID", "State"])

        for lb in lb_data:
            writer.writerow([
                lb['LoadBalancerName'],
                lb['LoadBalancerArn'],
                lb['Type'],
                lb['Scheme'],
                lb['DNSName'],
                lb['VpcId'],
                lb['State']
            ])

def main():
    # Get resources by subnet
    subnet_resources = list_subnets_and_resources()

    # Get WAF associations
    waf_data = list_waf_associations()

    # Get Load Balancers
    lb_data = list_load_balancers()

    # Collect EC2 instance data for CSV
    instances = []
    reservations = ec2_client.describe_instances()['Reservations']
    for reservation in reservations:
        for instance in reservation['Instances']:
            instances.append({
                'InstanceId': instance['InstanceId'],
                'State': instance['State']['Name'],
                'SubnetId': instance['SubnetId'],
                'PrivateIpAddress': instance.get('PrivateIpAddress'),
                'PublicIpAddress': instance.get('PublicIpAddress'),
                'SecurityGroups': instance.get('SecurityGroups', []),
                'Volumes': instance.get('BlockDeviceMappings', []),
                'Tags': instance.get('Tags', [])
            })

    # Export data to CSVs
    export_subnets_to_csv(subnet_resources)
    export_waf_to_csv(waf_data)
    export_instances_to_csv(instances)
    export_load_balancers_to_csv(lb_data)

    print("Data exported to subnets_Saude.csv, waf_associations_Saude.csv, instances_Saude.csv, and load_balancers_Saude.csv")

if __name__ == "__main__":
    main()
