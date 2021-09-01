import sys
import os
import json
import boto3
import hashlib
from lambdaroute import router, HTTPException
import simple_acme_dns
from aws_helper import Route53ChallengeCompleter, S3Helper, ACMHelper

app = router()
DIRECTORY_STAGE_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"


def lambda_handler(event, context):
    # print(json.dumps(event, indent=4))
    h = event["headers"]
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
    event["x-user"] = user
    return app.serve(event.get('resource'), event)

@app.route('/get_certificate')
def get_certificate(event):

    print(json.dumps(event, indent=4))

    doms = event["queryStringParameters"].get("domains", "").split(",")
    prod = event["queryStringParameters"].get("prod", False)
    user = event["queryStringParameters"].get("user", "glenkmurray@armyspy.com")
    session = boto3.Session()
    r53 = Route53ChallengeCompleter(session)
    s3 = S3Helper(session)
    acm = ACMHelper(session)
    client = simple_acme_dns.ACMEClient(
        domains=doms,
        email=user,
        directory= DIRECTORY_URL if prod else DIRECTORY_STAGE_URL,
        nameservers=["8.8.8.8", "1.1.1.1"],    # Set the nameservers to query when checking DNS propagation
        generate_csr=False,    # Generate a new private key and CSR upon creation of our object
        new_account=False,
    )

    cfg_file = "{}/cfg.json".format(user)
    cfg = s3.get_json(cfg_file)
    if cfg != {}:
        print("re-using old registration")
        client = simple_acme_dns.ACMEClient.load_account(cfg)
        client.generate_csr()
    else:
        print("creating new account")
        client.new_account()
        client.generate_private_key_and_csr("rsa2048")
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

    # Start waiting for DNS propagation before requesting the certificate
    # Keep checking DNS for the verification token for 60 seconds (1 minutes) before giving up.
    # If a DNS query returns the matching verification token, request the certificate. Otherwise, deactivate the account.
    print("waiting propagation")
    r53.wait_for_bulk_changes()

    if client.check_dns_propagation(timeout=60, interval=1):
        print("requesting certificate")
        client.request_certificate()
        base_name = "{}/ssl/{}".format(user, doms[0])
        print("saving on s3 on path : {}".format(base_name))

        s3.put_file("{}.pem".format(base_name), client.certificate.decode())
        s3.put_file("{}.key".format(base_name), client.private_key.decode())
        s3.put_file("{}.csr".format(base_name), client.csr.decode())

        # with open("{}.pem".format(doms[0]), "w") as file1:
        #     file1.write(client.certificate.decode())

        # with open("{}.key".format(doms[0]), "w") as file1:
        #     file1.write(client.private_key.decode())
        print("Saving to ACM")
        acm.upload_cert_to_acm(
            doms[0],
            client.private_key.decode(),
            client.certificate.decode(),
        )

    print("cleaup dns challange")
    for r in dns_records:
        r53.delete_txt_record(r["zone_id"], r["record"], r["value"])
    print("dns challange removed")



