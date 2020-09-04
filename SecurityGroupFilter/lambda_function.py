import boto3
import ipaddress
import os
import copy
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ast
import base64
import logging


ip_list = []
if os.environ['SECURITY_GROUPS_LIST'] != "":
    ip_list = os.environ['SECURITY_GROUPS_LIST'].split(',')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_secret(secret_name, region_name):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    get_secret_value_response = client.get_secret_value(
        SecretId=secret_name
    )
    # Decrypts secret using the associated KMS CMK.
    # Depending on whether the secret is a string or binary, one of these fields will be populated.
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
        return secret
    else:
        decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return decoded_binary_secret


class FileOpener:
    """
    Class to cache file contents.
    """
    file_cache = {}

    @staticmethod
    def open_file(filename):
        if filename not in FileOpener.file_cache:
            with open(filename) as fp:
                FileOpener.file_cache[filename] = fp.read()
        return FileOpener.file_cache[filename]


def modify_security_group(group_id):
    """
    Modify Security Group if it has invalid rules.
    :param group_id: ID of security group.
    :return: True if Security group is modified, False otherwise.
    """
    exceptions = {}
    logger.info(group_id)
    ec2_resource = boto3.resource('ec2')
    security_group = ec2_resource.SecurityGroup(group_id)
    ingress_rules = security_group.ip_permissions
    removed_rules = []
    added_rules = []
    modified = False

    removed_rules_list = []

    for ingress_rule in ingress_rules:
        ingress_rule_dict = {}
        key_list = ['FromPort', 'ToPort', 'IpProtocol']
        for key in key_list:
            if key in ingress_rule:
                ingress_rule_dict[key] = ingress_rule[key]
        is_exception = False
        if group_id in exceptions:
            for exception in exceptions[group_id]:
                if exception == ingress_rule_dict:
                    is_exception = True
                    break
        if is_exception:
            continue
        invalid_ipv4_found = False
        new_rule = copy.deepcopy(ingress_rule)
        updated_ipv4_list = []
        updated_ipv4_addr_set = set()
        if 'IpRanges' in ingress_rule:
            for ipv4_rule in ingress_rule['IpRanges']:
                ipv4_cidr = ipv4_rule['CidrIp']
                addr = ipaddress.IPv4Network(ipv4_cidr, strict=False)
                if ipv4_cidr == '0.0.0.0/0':
                    invalid_ipv4_found = True
                else:
                    updated_ipv4_addr_set.add(addr)
        if invalid_ipv4_found:
            for allowed_cidr in ip_list:
                allowed_cidr_addr = ipaddress.IPv4Network(allowed_cidr, strict=False)
                updated_ipv4_addr_set.add(allowed_cidr_addr)
            for addr in updated_ipv4_addr_set:
                updated_ipv4_list.append({'CidrIp': str(addr)})
            new_rule['IpRanges'] = updated_ipv4_list

        invalid_ipv6_found = False
        updated_ipv6_list = []
        updated_ipv6_addr_set = set()
        if 'Ipv6Ranges' in ingress_rule:
            for ipv6_rule in ingress_rule['Ipv6Ranges']:
                ipv6_cidr = ipv6_rule['CidrIpv6']
                addr = ipaddress.IPv6Network(ipv6_cidr, strict=False)
                if ipv6_cidr == '::/0':
                    invalid_ipv6_found = True
                else:
                    updated_ipv6_addr_set.add(addr)
        if invalid_ipv6_found:
            for addr in updated_ipv6_addr_set:
                updated_ipv6_list.append({'CidrIpv6': str(addr)})
            new_rule['Ipv6Ranges'] = updated_ipv6_list

        if invalid_ipv4_found or invalid_ipv6_found:
            removed_rules.append(ingress_rule)
            removed_rules_list.append(ingress_rule_dict)
            added_rules.append(new_rule)
            modified = True

    logger.info(ingress_rules)
    logger.info(removed_rules)
    logger.info(added_rules)

    if modified:
        security_group.revoke_ingress(IpPermissions=removed_rules)
        response = security_group.authorize_ingress(IpPermissions=added_rules)
        logger.info(response)

    return modified, removed_rules_list


def send_email(email_body):
    """
    Sends email according to environment variables.
    :param email_body: Body of email.
    :return: None
    """
    msg = MIMEMultipart('alternative')
    email = os.environ['EMAIL_FROM']
    try:
        secret_value = get_secret(os.environ['SECRET_NAME'], 'us-east-2')
    except Exception as e:
        logger.exception("Exception while trying to get password from Secrets Manager")
        return
    password = ast.literal_eval(secret_value)[os.environ['SECRET_KEY_NAME']]
    msg['Subject'] = os.environ["EMAIL_SUBJECT"]
    msg['From'] = email
    you = os.environ['EMAIL_TO'].split(',')
    msg['To'] = ", ".join(you)
    body = email_body
    msg.attach(MIMEText(body, 'html'))
    try:
        smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
        smtpObj.starttls()
        smtpObj.login(email, password)
        smtpObj.sendmail(email, you, msg.as_string())
        smtpObj.quit()
        logger.info('Email sent')
    except smtplib.SMTPException as e:
        logger.info("Error: unable to send email due to", e)


def generate_email_body(environment, region, group_id, identity, removed_rules_list):
    """
    Generate HTML email body dynamically on basis of variables passed.
    :param environment: Account Identifier.
    :param region: AWS region.
    :param group_id: Security Group ID.
    :param identity: Username or ARN which made the change.
    :param removed_rules_list: List of security group rules which were removed.
    :return: The formatted email body.
    """
    email_body = FileOpener.open_file('email_body.html')
    table_rows = ''
    for rule in removed_rules_list:
        table_row = FileOpener.open_file('table_row.html')
        table_row_dict = {'FromPort': 'N/A', 'ToPort': 'N/A', 'IpProtocol': 'N/A'}
        key_list = ['FromPort', 'ToPort', 'IpProtocol']
        for key in key_list:
            if key in rule:
                if str(rule[key]) == '-1':
                    table_row_dict[key] = 'All'
                else:
                    table_row_dict[key] = str(rule[key])
        table_rows += table_row.format(group_id, table_row_dict['IpProtocol'], table_row_dict['FromPort'],
                                       table_row_dict['ToPort'])
    return email_body.format(environment, region, identity, table_rows)


def check_for_arn_exception(arn):
    """
    Checks whether ARN of triggering identity is in exception.
    :param arn: The arn of triggering identity.
    :return: True if in exception, False otherwise.
    """
    exception_arns = [os.environ['AWS_LAMBDA_FUNCTION_NAME']]
    if any(arn.endswith(exception_arn) for exception_arn in exception_arns):
        logger.info("Exception ARN")
        return True
    return False


def check_for_group_exception(group_id):
    """
    Checks whether security group is in exception.
    :param group_id: ID of the Security group on which modifications were made.
    :return: True if in exception, False otherwise.
    """
    exception_groups = os.environ['EXCEPTION_GROUP_IDS'].split(',')
    if group_id in exception_groups:
        logger.info("{} is in exception".format(group_id))
        return True
    return False


def generate_and_send_email(event, removed_rules_list):
    """
    Generate email body and send email when a violation is found.
    :param event: Triggering event
    :param removed_rules_list: List of rules removed.
    :return: None
    """
    group_id = event["detail"]["requestParameters"]["groupId"]
    environment = os.environ["ENVIRONMENT_NAME"]
    region = event["detail"]["awsRegion"]

    if "userName" in event["detail"]["userIdentity"]:
        identity = event["detail"]["userIdentity"]["userName"]
    else:
        identity = event["detail"]["userIdentity"]["arn"]

    email_body = generate_email_body(environment, region, group_id, identity, removed_rules_list)
    send_email(email_body)


def lambda_handler(event, context):
    arn = event["detail"]["userIdentity"]["arn"]
    group_id = event["detail"]["requestParameters"]["groupId"]

    # Precaution against Lambda triggering indefinitely and Check for Security Groups in exception.
    if check_for_arn_exception(arn) or check_for_group_exception(group_id):
        return

    modified, removed_rules_list = modify_security_group(group_id)
    if modified:
        generate_and_send_email(event, removed_rules_list)
