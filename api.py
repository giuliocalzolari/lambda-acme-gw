import sys
import re
import os
import json
import boto3
import hashlib
from lambdaroute import router, HTTPException
from aws_helper import SFNHelper, S3Helper, ApigwHelper
app = router()
api = ApigwHelper()


def lambda_handler(event, context):
    rs = api.validate(event)
    if api.error:
        return rs
    return app.serve(event.get('resource'), api.event)

@app.route('/get_certificate')
def get_certificate(event):
    domains = api.read_input("domains")
    if not domains:
        return {
            "msg": "domains argv not provided",
        }, 400

    user = api.read_input("user")
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not re.fullmatch(regex, user):
        return {
            "msg": "user argv not provided or incorrect",
        }, 400

    session = boto3.Session()
    sfn = SFNHelper(session)
    argv = {
        "domains": domains,
        "user": user,
    }
    print(f"User: {argv['user']} requested cert for {argv['domains']}")
    uuid = sfn.invoke_sfn(argv)
    out = {
        "msg": "execution in progress",
        "id": uuid
    }

    if event["queryStringParameters"].get("autorenew", False):
        print("trigger auto-renew process")
        out["renew_uuid"] = sfn.invoke_sfn_renew(argv)

    return out, 202


@app.route('/get_certificate_worker')
def get_certificate(event):
    # print(json.dumps(event, indent=4))
    session = boto3.Session()
    sfn = SFNHelper(session)

    uuid = event.get("queryStringParameters", {}).get("id", None)
    if not uuid:
        return "exection id wrong", 500
    else:
        return sfn.describe_execution(uuid), 200


@app.route('/download_certificate')
def get_certificate(event):
    session = boto3.Session()
    sfn = SFNHelper(session)
    s3 = S3Helper(session)

    uuid = event.get("queryStringParameters", {}).get("id", None)
    private_key = bool(event.get("queryStringParameters", {}).get("key", False))
    csr = bool(event.get("queryStringParameters", {}).get("csr", False))
    if not uuid:
        return "wrong id", 500

    rs = sfn.describe_execution(uuid)
    if rs["status"] != "SUCCEEDED":
        return "execution status : {}".format(rs["status"]), 204

    out = {
        "cert": s3.generate_presigned_url(rs["output"]["s3_cert"])
    }
    if private_key:
       out["key"] = s3.generate_presigned_url(rs["output"]["s3_key"])

    if csr:
        out["csr"] = s3.generate_presigned_url(rs["output"]["s3_csr"])

    return out , 200
