from flask import Flask, jsonify
from gevent.wsgi import WSGIServer
from collections import deque

import logging
import binascii
import decimal


class Logger(object):
    """ A dummy file object to allow using a logger to log requests instead
    of sending to stderr like the default WSGI logger """
    logger = None

    def write(self, s):
        self.logger.info(s.strip())


class ReverseProxied(object):
    '''Wrap the application in this middleware and configure the
    front-end server to add these headers, to let you quietly bind
    this to a URL other than / and to an HTTP scheme that is
    different than what is used locally.

    In nginx:
    location /myprefix {
        proxy_pass http://192.168.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Script-Name /myprefix;
        }

    :param app: the WSGI application
    '''
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            path_info = environ['PATH_INFO']
            if path_info.startswith(script_name):
                environ['PATH_INFO'] = path_info[len(script_name):]

        scheme = environ.get('HTTP_X_SCHEME', '')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)


class ServerMonitor(WSGIServer):
    """ Provides a few useful json endpoints for viewing server health and
    performance. """
    def __init__(self, manager):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.manager = manager
        self.settings = self.manager.settings
        app = Flask(__name__)
        app.wsgi_app = ReverseProxied(app.wsgi_app)
        app.add_url_rule('/', 'general', self.general)
        self.app = app

    def start(self, *args, **kwargs):
        WSGIServer.__init__(self, self.settings['ui_address'], self.app,
                            spawn=100, log=Logger())

        self.logger.info("Monitoring port listening on {}"
                         .format(self.settings['ui_address']))

        # Monkey patch the wsgi logger
        Logger.logger = self.logger
        WSGIServer.start(self, *args, **kwargs)

    def stop(self, *args, **kwargs):
        WSGIServer.stop(self)
        self.logger.info("Exit")

    def general(self):
        conns = []
        for conn in self.manager.peermgr.peers:
            conns.append(dict(height=conn.remote_height,
                              protocol_version=conn.ver_send,
                              client_version=conn.client_version,
                              address="{}:{}".format(conn.dstaddr, conn.dstport)))

        data = dict(height=self.manager.chaindb.getheight(),
                    hash=binascii.hexlify(self.manager.chaindb.gettophash()[::-1]),
                    peer_count=len(self.manager.peermgr.peers),
                    peers=conns)

        return jsonify(jsonize(data))


def jsonize(item):
    """ Recursive function that converts a lot of non-serializable content
    to something json.dumps will like better """
    if isinstance(item, dict):
        new = {}
        for k, v in item.iteritems():
            k = str(k)
            if isinstance(v, deque):
                new[k] = jsonize(list(v))
            else:
                new[k] = jsonize(v)
        return new
    elif isinstance(item, list) or isinstance(item, tuple):
        new = []
        for part in item:
            new.append(jsonize(part))
        return new
    else:
        if isinstance(item, str):
            return item.encode('string_escape')
        elif isinstance(item, set):
            return list(item)
        elif isinstance(item, decimal.Decimal):
            return float(item)
        elif isinstance(item, (int, long, bool, float)) or item is None:
            return item
        elif hasattr(item, "__dict__"):
            return {str(k).encode('string_escape'): str(v).encode('string_escape')
                    for k, v in item.__dict__.iteritems()}
        else:
            return str(item)
