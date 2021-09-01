acme-gw



curl  -H 'X-Token: giuliocalzo:212782e659872e1136a2ecdcb5ab9feb' "https://voricpk5l4.execute-api.eu-west-1.amazonaws.com/prod/get_certificate?user=giuliocalzo@gmail.com&domains=acme.gc.crlabs.cloud,demo.acme.gc.crlabs.cloud"



tk = "{}{}".format('giuliocalzo', '${{ssm:/timecard/prod/apitoken}}').encode()