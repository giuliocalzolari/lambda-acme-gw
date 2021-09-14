import json
import logging
from urllib.parse import parse_qs

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class HTTPException(Exception):
    def __init__(self, message, code=500):
        self.message = message
        self.code = code # you could add more args
    def __str__(self):
        return str(self.message)

class router():
    def __init__(self):
        self.routes = {}

    @staticmethod
    def parse_body(body):
        try:
            arguments = json.loads(body)
        except ValueError:
            logging.exception('Cannot parse body "{}"'.format(body))
            _args = parse_qs(body)
            arguments = {k: v[0] if len(v) == 1 else v for k, v in _args.items()}
        except Exception:
            arguments = {}

        return arguments

    def route(self, route_str):
        def decorator(f):
            self.routes[route_str] = f
            return f

        return decorator

    def serve(self, path, event=None):
        try:
            first_branch_path = '/'.join(path.split('/')[:2])
            view_function = self.routes[first_branch_path]
            # parse body
            event['body'] = self.parse_body(event.get('body'))
            results, code = view_function(event)
        except HTTPException as e:
            logging.error('Error with the route "{}"'.format(path))
            code = e.code
            results = {
                'message': e.message,
                'error': 'Error with the route "{}"'.format(path),
            }
        except (ValueError, KeyError, AttributeError) as e:
            logging.exception('Error with the route "{}"'.format(path))
            code = 501
            results = {
                'message': e.message if hasattr(e, 'message') else str(e),
                'error': 'Error with the route "{}"'.format(path)
            }
        except (Exception) as e:
            logging.exception('Exception while executing route "{}"'.format(path))
            code = 418
            results = {
                'message': 'Please contact developer',
                'error': 'Error'
            }

        logger.info(results)
        return {
                'statusCode': code,
                'headers': {'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Credentials': True},
                'body': json.dumps(results, indent=2, default=str)
            }
