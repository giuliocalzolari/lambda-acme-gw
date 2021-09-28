from re import S
import time
import boto3
import re
import os
import json
import uuid
import hashlib

class ApigwHelper(object):
    def __init__(self):
        self.error = True

    def validate(self, event):
        self.event = event
        if os.environ.get("DEBUG", "none") == "enable":
            print(json.dumps(event, indent=4))

        h = self.event["headers"]
        if "x-token" not in h:
            return  {
                "statusCode": 500,
                "body": 'X-Token is missing'
            }
        elif ":" not in h["x-token"]:
            return  {
                "statusCode": 500,
                "body": 'X-Token incorrect'
            }

        user, passwd = h["x-token"].split(":")
        tk = "{}{}".format(user, os.environ.get("XTOKEN", "xxx")).encode()
        if passwd != hashlib.md5(tk).hexdigest():
            return  {
                "statusCode": 403,
                "body": 'x-token wrong'
            }
        self.error = False
        self.event["x-user"] = user
        return self.event

    def read_input(self, key):
        if self.event.get("queryStringParameters", None) is not None:
            return self.event.get("queryStringParameters", {}).get(key, None)

        if self.event.get("body", None) is not None:
            return self.event.get("body", {}).get(key, None)
        return False

    def valid_uuid(self, uuid):
        regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)
        match = regex.match(uuid)
        return bool(match)

    def valid_email(self, email):
        regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        return bool(re.search(regex,email))


class S3Helper(object):
    def __init__(self, s3=None):
        self.client = boto3.client("s3")
        self.bucket = os.environ.get("S3_BUCKET", s3)


    def generate_presigned_url(self, key, expiration=3600):
        tmp = key.replace("s3://", "").split("/")
        bucket_name = tmp[0]
        tmp.pop(0)
        return self.client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': "/".join(tmp)},
                                                    ExpiresIn=expiration)

    def get_json(self, key):
        try:
            return json.loads(self.get_file(key))
        except json.decoder.JSONDecodeError as e:
            return ""

    def put_json(self, key, value):
        _json = json.dumps(value,indent=4, default=str)
        return self.put_file(key, _json)

    def put_file(self, key, value):
        self.client.put_object(
            Body=value,
            Bucket=self.bucket,
            Key=key
        )
        return "s3://{}/{}".format(self.bucket, key)

    def get_file(self, key):
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
            return obj['Body'].read().decode()
        except self.client.exceptions.NoSuchKey:
            return ""



class SFNHelper(object):
    def __init__(self, s3=None):
        self.client = boto3.client("stepfunctions")
        self.step_function_arn = os.environ.get("SFN_ARN", s3)
        if not self.step_function_arn:
            raise Exception("[SFN_ARN] OS variable is not set")

    def invoke_sfn(self, event, prefix = ""):
        _uuid = str(uuid.uuid4())
        self.client.start_execution(
                    stateMachineArn=self.step_function_arn,
                    name=f"{prefix}{_uuid}",
                    input=json.dumps(event)
                )
        return _uuid

    def invoke_sfn_renew(self, event):
        _uuid = str(uuid.uuid4())
        seconds_in_day = 86400
        event["wait"] = 86 * seconds_in_day
        self.client.start_execution(
                    stateMachineArn=self.step_function_arn.replace("gw","renew"),
                    name=f"renew-{_uuid}",
                    input=json.dumps(event)
                )
        return _uuid


    def describe_execution(self, uuid):
        execution_arn = self.step_function_arn.replace("stateMachine", "execution")
        response = self.client.describe_execution(
                    executionArn="{}:{}".format(execution_arn, uuid)
                )
        return {
            "status": response["status"],
            "output": json.loads(response.get("output", "{}")),
        }



class ACMHelper(object):
    def __init__(self, domain=None):
        self.client = boto3.client("acm")

    def find_existing_cert(self, domain):
        paginator = self.client.get_paginator('list_certificates')
        iterator = paginator.paginate(PaginationConfig={'MaxItems':1000})
        for page in iterator:
            for cert in page['CertificateSummaryList']:
                cert = self.client.describe_certificate(CertificateArn=cert['CertificateArn'])
                # print(cert['Certificate'])
                if domain in cert['Certificate']['SubjectAlternativeNames']:
                    return cert

        return None

    def parse_full_chain(self, chain):
        BEGIN="-----BEGIN CERTIFICATE-----"
        END="-----END CERTIFICATE-----"
        chain = chain.replace(END, "")
        cert_slots = chain.split(BEGIN)
        cert_slots = list(filter(None, cert_slots))
        cert = cert_slots[0].lstrip().rstrip()
        certificate = "{}\n{}\n{}".format(BEGIN,cert,END)
        cert_slots.pop(0)
        chain = ""
        for c in cert_slots:
            cert = c.lstrip().rstrip()
            chain += "{}\n{}\n{}\n".format(BEGIN,cert,END)

        return certificate, chain

    def upload_cert_to_acm(self, domains, private_key, chain):
        certificate, chain = self.parse_full_chain(chain)
        kwargs = {
            "Certificate": certificate,
            "PrivateKey": private_key,
            "CertificateChain": chain,
        }
        existing_cert = self.find_existing_cert(domains)
        certificate_arn = existing_cert['Certificate']['CertificateArn'] if existing_cert else None
        if existing_cert:
            # print(f"found: {certificate_arn}")
            kwargs["CertificateArn"] = certificate_arn
        acm_response = self.client.import_certificate(**kwargs)

        return acm_response['CertificateArn']




class SSMHelper(object):
    def __init__(self, key_id=None, prefix = "/acme"):
        self.client = boto3.client("ssm")
        self.key_id = os.environ.get("SSM_KMS_ID", key_id)
        self.prefix = prefix

    def get_params(self, key):
        cfg = {}
        if not key.endswith("/"):
            key = f"{key}/"

        if "@" in key:
            key = key.replace("@", "____")

        print(key)
        data = self.client.get_parameters_by_path(
            Path="{}/{}".format(self.prefix, key),
            Recursive=True,
            WithDecryption=True,
        )
        for parm in data["Parameters"]:
            key_name = parm["Name"].replace("{}/{}/".format(self.prefix, key) , "")
            if cfg.get(key_name, "") == "":
                cfg[key_name] = parm["Value"]
        return cfg

    def write_param(self, key, value):

        if "@" in key:
            key = key.replace("@", "____")
        print(len(value))
        self.client.put_parameter(
            Name="{}/{}/cfg".format(self.prefix, key),
            Value=value,
            Type='SecureString',
            Overwrite=True,
            KeyId=self.key_id
        )


class Route53ChallengeCompleter(object):
    def __init__(self):
        route53_client = boto3.client("route53")
        self.route53_client = route53_client
        self.change_ids = []

    def _find_zone_id_for_domain(self, domain):
        paginator = self.route53_client.get_paginator("list_hosted_zones")
        zones = []
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if (
                    domain.endswith(zone["Name"]) or
                    (domain + ".").endswith(zone["Name"])
                ) and not zone["Config"]["PrivateZone"]:
                    zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise ValueError(
                "Unable to find a Route53 hosted zone for {}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the last one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action, zone_id, domain, value):
        response = self.route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": 30,
                            "ResourceRecords": [
                                # For some reason TXT records need to be
                                # manually quoted.
                                {"Value": '"{}"'.format(value)}
                            ],
                        }
                    }
                ]
            }
        )
        self.change_ids.append(response["ChangeInfo"]["Id"])
        return response["ChangeInfo"]["Id"]

    def create_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record(
            "UPSERT",
            zone_id,
            host,
            value,
        )
        self.change_ids.append(change_id)
        return (zone_id, change_id)

    def delete_txt_record(self,zone_id, host, value):

        try:
            self._change_txt_record(
                "DELETE",
                zone_id,
                host,
                value
            )
        except self.route53_client.exceptions.InvalidChangeBatch as e:
            print("handled: " + str(e))


    def wait_for_change(self, change_id):
        while True:
            response = self.route53_client.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(1)

    def wait_for_bulk_changes(self):
        while True:
            # print(self.change_ids)
            for change_id in self.change_ids:
                response = self.route53_client.get_change(Id=change_id)
                # print(response["ChangeInfo"]["Status"])
                if response["ChangeInfo"]["Status"] == "INSYNC":
                    self.change_ids.remove(change_id)
                time.sleep(1)
            if self.change_ids == []:
                break


