import sys
import os
import json
import boto3
import hashlib
from lambdaroute import router, HTTPException
from aws_helper import SFNHelper, S3Helper
app = router()


def lambda_handler(event, context):
    print(json.dumps(event, indent=4))
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
    session = boto3.Session()
    sfn = SFNHelper(session)

    uuid = sfn.invoke_sfn(event)
    return {
        "msg": "execution in progress",
        "id": uuid
    }, 202


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

    out = s3.get_file_url(rs["output"]["s3_cert"])
    if private_key:
        out += s3.get_file_url(rs["output"]["s3_key"])

    if csr:
        out += s3.get_file_url(rs["output"]["s3_csr"])

    return out , 200
