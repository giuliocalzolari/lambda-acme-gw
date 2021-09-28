import sys
import json
import boto3
from lambdaroute import router
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
    if not api.valid_email(user):
        return {
            "msg": "user argv not provided or incorrect",
        }, 400

    sfn = SFNHelper()
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

    if bool(api.read_input("autorenew")):
        print("trigger auto-renew process")
        out["renew_uuid"] = sfn.invoke_sfn_renew(argv)

    return out, 202


@app.route('/get_certificate_worker')
def get_certificate(event):
    sfn = SFNHelper()

    uuid = api.read_input("id")
    if not api.valid_uuid(uuid):
        return {
            "msg": "exection id not provided or incorrect",
        }, 500

    return sfn.describe_execution(uuid), 200


@app.route('/download_certificate')
def get_certificate(event):
    sfn = SFNHelper()
    s3 = S3Helper()

    uuid = api.read_input("id")
    private_key = bool(api.read_input("key"))
    csr = bool(api.read_input("csr"))

    if not api.valid_uuid(uuid):
        return {
            "msg": "exection id not provided or incorrect",
        }, 500

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
