import sys
import os
import json
import boto3
from OpenSSL import crypto
from datetime import datetime, timedelta
import simple_acme_dns
from aws_helper import Route53ChallengeCompleter, S3Helper, ACMHelper, SFNHelper

DIRECTORY_STAGE_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

session = boto3.Session()
r53 = Route53ChallengeCompleter()
s3 = S3Helper()
acm = ACMHelper()
sfn = SFNHelper()

def acme_process(doms, user):
    base_name = "{}/ssl/{}".format(user, doms[0])
    client = simple_acme_dns.ACMEClient(
            domains=doms,
            email=user,
            directory=os.environ.get("DIRECTORY_URL", DIRECTORY_STAGE_URL),
            nameservers=["8.8.8.8", "1.1.1.1"],    # Set the nameservers to query when checking DNS propagation
            generate_csr=False,    # Generate a new private key and CSR upon creation of our object
            new_account=False,
        )

    cfg_file = "{}/cfg.json".format(user)
    cfg = s3.get_json(cfg_file)
    if cfg != {}:
        print("Re-using old registration")
        client = simple_acme_dns.ACMEClient.load_account(cfg)
        client.domains = doms
        client.generate_csr()
    else:
        print("Creating new account")
        client.new_account()
        client.generate_private_key_and_csr()
        cfg = client.export_account(
            save_certificate=True,
            save_private_key=True,
        )
        s3.put_json(cfg_file, cfg)
    dns_records=[]
    # Request the verification token for our DOMAIN. Print the challenge FQDN and it's corresponding token.
    for domain, token in client.request_verification_tokens():
        print("{domain} --> {token}".format(domain=domain, token=token))
        zone_id = r53._find_zone_id_for_domain(domain)
        dns_records.append({
            "zone_id": zone_id,
            "record": domain,
            "value": token,
        })
        r53._change_txt_record("UPSERT", zone_id, domain, token)
    print("Waiting Route53 propagation")
    r53.wait_for_bulk_changes()

    if client.check_dns_propagation(timeout=60, interval=1):
        print(f"Requesting ACME certificate for {doms}")
        client.request_certificate()
        print("Saving on s3 on path : {}".format(base_name))
        s3_cert = s3.put_file("{}.pem".format(base_name), client.certificate.decode())
        s3_key = s3.put_file("{}.key".format(base_name), client.private_key.decode())
        s3_csr = s3.put_file("{}.csr".format(base_name), client.csr.decode())

    print("Cleaup dns challange")
    for r in dns_records:
        r53.delete_txt_record(r["zone_id"], r["record"], r["value"])
    print("DNS challange removed")

    return s3_cert, s3_key, s3_csr, client.certificate.decode(), client.private_key.decode()


def lambda_handler(argv, context=None):
    doms = argv.get("domains", "").split(",")
    user = argv.get("user", "glenkmurray@armyspy.com")
    base_name = "{}/ssl/{}".format(user, doms[0])
    acme_api = True
    if "wait" in argv:
        print(f"Auto Renew process for {base_name} for domains: {doms}")
    else:
        print(f"Standard request: {base_name} for domains: {doms}")
    cert_body = s3.get_file("{}.pem".format(base_name))

    if cert_body == "": # cert does not exist
        msg = " cert {}.pem  empty".format(base_name)
    else:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_body)
        not_after = datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
        now = datetime.now()
        if now > not_after:
            msg = f"The certificate provided is expired: {not_after}, Renew!!!"
        elif now > (not_after - timedelta(days=5)):
            msg = f"The certificate provided is not expired yet: BUT is better to renew"
        else:
            # check SAN names
            ext_count = cert.get_extension_count()
            for i in range(ext_count):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    domain_certs = ext.__str__().replace(", ", "").split("DNS:")
                    domain_certs.pop(0)

            if set(domain_certs) != set(doms):
                msg = "SAN names mismatch... better to renew"
            else:
                acme_api = False
                msg = "Cert on S3 is valid and not expired"
                key_body = s3.get_file("{}.key".format(base_name))
                s3_cert = "s3://{}/{}".format(s3.bucket, "{}.pem".format(base_name))
                s3_key = "s3://{}/{}".format(s3.bucket, "{}.key".format(base_name))
                s3_csr = "s3://{}/{}".format(s3.bucket, "{}.csr".format(base_name))
    print(msg)
    if acme_api:
        s3_cert, s3_key, s3_csr, cert_body, key_body = acme_process(doms, user)

    response = {
        "s3_cert": s3_cert,
        "s3_key": s3_key,
        "s3_csr": s3_csr,
    }
    print("Saving to ACM")
    response["acm"] = acm.upload_cert_to_acm(
        doms[0],
        key_body,
        cert_body,
    )
    return response