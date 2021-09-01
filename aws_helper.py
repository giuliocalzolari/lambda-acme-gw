from re import S
import time
import boto3
import os
import json


class S3Helper(object):
    def __init__(self, session, s3=None):
        self.client = session.client("s3")
        self.bucket = os.environ.get("S3_BUCKET", s3)

    def get_json(self, key):
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
            return json.loads(obj['Body'].read())
        except self.client.exceptions.NoSuchKey:
            return {}

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


class ACMHelper(object):
    def __init__(self, session, domain=None):
        self.client = session.client("acm")

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

        return None if certificate_arn else acm_response['CertificateArn']




class SSMHelper(object):
    def __init__(self, session, key_id=None, prefix = "/acme"):
        self.client = session.client("ssm")
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
    def __init__(self, session):
        route53_client = session.client("route53")
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
            print(self.change_ids)
            for change_id in self.change_ids:
                response = self.route53_client.get_change(Id=change_id)
                print(response["ChangeInfo"]["Status"])
                if response["ChangeInfo"]["Status"] == "INSYNC":
                    self.change_ids.remove(change_id)
                time.sleep(1)
            if self.change_ids == []:
                break


