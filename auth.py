
from __future__ import print_function

import os
import re
import json
import logging
import base64
import boto3
import secrets
import hashlib
from datetime import timedelta, datetime
import time


dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['DYNAMO_USER_TABLE'])
log_level = os.environ.get('LOG_LEVEL', "INFO")
log = logging.getLogger(__name__)
logging.getLogger().setLevel(log_level)
BEARER_TOKEN_PATTERN = re.compile('^Bearer[ ]+([^ ]+)[ ]*$', re.I)


def get_from_ddb(key):
    dynamodbClient = boto3.client('dynamodb')
    epochTimeNow = int(time.time())
    try:
        res = dynamodbClient.query(
            TableName = os.environ['DYNAMO_TOKEN_TABLE'],
            KeyConditionExpression = '#username = :username',
            FilterExpression = '#t > :ttl',
            ExpressionAttributeNames = {
                '#t': 'ttl',
                '#username': 'username'
            },
            ExpressionAttributeValues = {
                ':ttl': {
                    'N': str(epochTimeNow),
                },
                ':username': {
                    'S': key
                }
            }
        )
        if 'Items' in res and len(res['Items']) >= 1:
            return res['Items']
        return None
    except Exception as e:
        print('Exception: ', e)
        return None

def db_check(event, username, username_password_hash, password):

    policy = AuthPolicy(event)
    log.debug("username: " + username)

    # Get the password from DynamoDB for the username
    item = table.get_item(ConsistentRead=True, Key={"username": username})
    if item.get('Item') is not None:
        log.debug("item: " + json.dumps(item))
        ddb_password = item.get('Item').get('password')
        log.debug("ddb_password:" + json.dumps(ddb_password))

        if ddb_password is not None:
            ddb_username_password = (username + ":" + ddb_password)
            ddb_username_password_hash = base64.standard_b64encode(ddb_username_password)
            log.debug("ddb_username_password_hash:" + ddb_username_password_hash)

            if username_password_hash == ddb_username_password_hash:
                policy.allowMethod(event['requestContext']['httpMethod'], event['path'])
                log.info("password match for: " + username)
            else:
                policy.denyMethod(event['requestContext']['httpMethod'], event['path'])
                log.info("password does not match for: " + username)
        else:
            log.info("No password found for username:" + username)
            policy.denyMethod(event['requestContext']['httpMethod'], event['path'])
    else:
        log.info("Did not find username: " + username)
        policy.denyMethod(event['requestContext']['httpMethod'], event['path'])

    # Finally, build the policy
    authResponse = policy.build()
    log.debug("authResponse: " + json.dumps(authResponse))
    return authResponse

def generate_token():
    token = secrets.token_urlsafe()
    expiration = datetime.now() + timedelta(hours=1)
    singrature_raw = "{}{}{}".format(token, expiration, os.environ.get("HASH", "42"))
    singrature = hashlib.sha256(singrature_raw.encode()).hexdigest()
    expiryTimestamp = int(time.mktime(expiration.timetuple()))

    boto3.client('dynamodb').put_item(
        TableName = os.environ['DYNAMO_TOKEN_TABLE'],
        Item = {
            'token': {
                'S': token
            },
            'singrature': {
                'S': singrature
            },
            'ttl': {
                'N': str(expiryTimestamp)
            }
        }
    )
    return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True
            },
            'body': json.dumps({
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "expire": expiration,
                    "signature": singrature
                }, default=str)
            }


def lambda_handler(event, context):
    # sourcery skip: extract-method, inline-immediately-returned-variable
    # log.debug("Event: " + json.dumps(event))
    print(json.dumps(event,indent=4, default=str))

    if event["resource"] == "/auth" and event["httpMethod"] == "POST":
        return generate_token()

    # Ensure the incoming Lambda event is for a request authorizer
    if event['type'] != 'REQUEST':
        raise Exception('Unauthorized')

    try:
        # Get authorization header in lowercase
        authorization_header = {k.lower(): v for k, v in event['headers'].items() if k.lower() == 'authorization'}
        log.debug("authorization: " + json.dumps(authorization_header))

        policy = AuthPolicy(event)
        match = BEARER_TOKEN_PATTERN.fullmatch(authorization_header['authorization'])
        if match is None:
            return policy.denyMethod(event['requestContext']['httpMethod'], event['path'])
        else:
            return policy.allowMethod(event['requestContext']['httpMethod'], event['path'])

        # Get the username:password hash from the authorization header
        # username_password_hash = authorization_header['authorization'].split()[1]
        # log.debug("username_password_hash: " + username_password_hash)

        # # Decode username_password_hash and get username
        # username , passwd = base64.standard_b64decode(username_password_hash).decode('utf-8').split(':')
        # authResponse = db_check(event, username, username_password_hash, passwd)

        # return authResponse
    except Exception:
        raise Exception('Unauthorized')


class HttpVerb:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ALL = "*"


class AuthPolicy(object):
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""


    def __init__(self, event):
        self.principalId = event['requestContext']['accountId']
        tmp = event['methodArn'].split(':')
        apiGatewayArnTmp = tmp[5].split('/')
        self.awsAccountId = tmp[4]
        self.restApiId = apiGatewayArnTmp[0]
        self.region = tmp[3]
        self.stage = apiGatewayArnTmp[1]
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        return {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements


    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])


    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy
