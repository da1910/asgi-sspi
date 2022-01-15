ASGI-SSPI
==============

ASGI-SSPI is `ASGI`_ Middleware which implements integrated windows authentication.
It makes it easy to add Integrated Windows Authentication to any ASGI application.

Its only dependency is `pyspnego`_ and it's been tested up to version 1.7.2

The official copy of this documentation is available at PLACEHOLDER.

Installation
------------

Install the extension with pip:

    $ pip install ASGI-SSPI

How to Use
----------

To integrate ``ASGI-SSPI`` into your application, simply pass your application
to the ``SPNEGOAuthMiddleware`` constructor.  All requests destined for the
application will first be authenticated by the middleware, and the authenticated
users principal will be available as the ``principal`` key in the ASGI
scope dictionary, under ``gssapi`` key.

For example::

    import uvicorn
    from asgi_sspi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [
                [b'content-type', b'text/plain'],
            ],
        })
        await send({
            'type': 'http.response.body',
            'body': b'Hello, {}'.format(scope['gssapi']['principal']),
        })

    app = SPNEGOAuthMiddleware(example)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


``ASGI-SSPI`` assumes that every request should be authenticated. If this is
not the case, you can override it by passing in a callback named
``auth_required_callback`` to the
``SPNEGOAuthMiddleware`` constructor. This callback will be called for every
request and passed the ASGI scope dictionary::

    import uvicorn
    from asgi_sspi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    def authenticate(scope):
        return scope['path'].startswith('/protected')

    app = SPNEGOAuthMiddleware(example,
                               auth_required_callback=authenticate)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


By default, when ``ASGI-SSPI`` responds with a ``401`` to indicate that
authentication is required, it generates a very simple page with a
``Content-Type`` of ``text/plain`` that includes the string ``Unauthorized``.

Similarly, when it responds with a ``403`` indicating that authentication has
failed, it generates another simple page with a ``Content-Type`` of
``text/plain`` that includes the string ``Forbidden``.

These can be customized::

    import uvicorn
    from asgi_sspi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    app = SPNEGOAuthMiddleware(example,
                               unauthorized='Authentication Required',
                               forbidden='Authentication Failed')

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)

You can also change the ``Content-Type`` by passing in full ASGI event tuples::

    import uvicorn
    from asgi_sspi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    forbidden=({
        'type': 'http.response.start',
        'status': 403,
        'headers': [
            [b'content-type', b'text/html'],
        ],
    }, {
        'type': 'http.response.body',
        'body': b'<html><body><h1>GO AWAY</h1></body></html>'
    })

    unauthorized=({
        'type': 'http.response.start',
        'status': 401,
        'headers': [
            [b'content-type', b'text/html'],
            [b'www-authenticate', b'negotiate'],
        ],
    }, {
        'type': 'http.response.body',
        'body': b'<html><body><h1>LOGIN FIRST</h1></body></html>'
    })

    app = SPNEGOAuthMiddleware(example,
                               unauthorized=unauthorized,
                               forbidden=forbidden)

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)

Hopefully, you are not using raw ASGI, and your framework of choice provides
a saner alternatives to full event definitions (like Starlette's Response class).


``ASGI-SSPI`` will authenticate the request using auto-resolved hostname.
You can change it, by providing the ``hostname`` argument to the constructor,
or defer to any hostname, present in keytab file, by providing an empty
string ``hostname`` argument to the constructor::

    import uvicorn
    from asgi_sspi import SPNEGOAuthMiddleware

    async def example(scope, receive, send):
        ... # same as above

    app = SPNEGOAuthMiddleware(example, hostname='example.com')

    if __name__ == '__main__':
        uvicorn.run(app, port=8080)


``ASGI-GSSAPI`` provides support for delegation. You do not need to
configure anything server-side, and it's up to the client to delegate the credentials.

How it works
------------

When an application which uses the middleware is accessed by a client, it will
check to see if the request includes authentication credentials in an
``Authorization`` header. If there are no such credentials, the application will
respond immediately with a ``401 Unauthorized`` response which includes a
``WWW-Authenticate`` header field with a value of ``Negotiate`` indicating to
the client that they are currently unauthorized, but that they can authenticate
using Negotiate authentication.

If credentials are presented in the ``Authorization`` header, the credentials
will be validated, the principal of the authenticating user will be extracted
and added to the ASGI scope using the key ``principal`` in the ``gssapi`` dictionary,
and the application will be called to serve the request. Send event will be hijacked
to append ``WWW-Authenticate`` header which identifies the server to
the client.  This allows ``ASGI-SSPI`` to support mutual authentication.


Full Example
------------

To see a simple example, you can download the code `from github
<http://github.com/washed-out/asgi-gssapi>`_. It is in the example directory.

Changes
-------

0.1.0 (2022-01-15)
``````````````````

-     initial implementation

History
=======
This plugin is copied wholesale from `AGSI-GSSAPI <https://github.com/washed-out/asgi-gssapi>`_,
which is itself a reimplementation `WSGI-Kerberos <https://github.com/deshaw/wsgi-kerberos>`_ .

The contributors and license information are maintained intact from both sources.

.. _ASGI: http://asgi.readthedocs.org/en/latest/
.. _pyspnego: https://pypi.org/project/pyspnego