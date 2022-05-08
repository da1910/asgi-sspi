import base64
from sys import platform

import pytest
from async_asgi_testclient import TestClient
from spnego._sspi import SSPIProxy
from spnego._negotiate import NegotiateProxy

from asgi_sspi import SPNEGOAuthMiddleware

# noinspection SpellCheckingInspection
CLIENT_TOKEN = "CTOKEN"
# noinspection SpellCheckingInspection
SERVER_TOKEN = b"STOKEN"
ENCODED_SERVER_TOKEN = base64.b64encode(SERVER_TOKEN).decode()

USE_SSPI = False
if platform == "win32":
    USE_SSPI = True


@pytest.fixture(autouse=True)
def disable_gssapi_flow(mocker):
    if USE_SSPI:
        mocker.patch("spnego._sspi.acquire_credentials_handle", lambda **kwargs: None)


@pytest.fixture
def successful_auth(mocker):
    if USE_SSPI:
        mocker.patch.object(SSPIProxy, "client_principal", "user@EXAMPLE.ORG")
        mocker.patch.object(SSPIProxy, "complete", True)
        step = mocker.patch.object(SSPIProxy, "step")
    else:
        mocker.patch.object(NegotiateProxy, "client_principal", "user@EXAMPLE.ORG")
        mocker.patch.object(NegotiateProxy, "complete", True)
        step = mocker.patch.object(NegotiateProxy, "step")
    decode = mocker.patch("base64.b64decode")
    yield step, decode


@pytest.fixture
def unsuccessful_auth(mocker):
    if USE_SSPI:
        mocker.patch.object(SSPIProxy, "client_principal", "user@EXAMPLE.ORG")
        mocker.patch.object(SSPIProxy, "complete", False)
        step = mocker.patch.object(SSPIProxy, "step")
    else:
        mocker.patch.object(NegotiateProxy, "client_principal", "user@EXAMPLE.ORG")
        mocker.patch.object(NegotiateProxy, "complete", False)
        step = mocker.patch.object(NegotiateProxy, "step")
    decode = mocker.patch("base64.b64decode")
    yield step, decode


async def index(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                [b"content-type", b"text/plain"],
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": ("Hello {}".format(scope["gssapi"].get("principal") or "ANONYMOUS")).encode(),
        }
    )


def quick_error(code: int, content: bytes, content_type: bytes, www_auth_header: bool = False):
    return [
        {
            "type": "http.response.start",
            "status": code,
            "headers": [
                [b"content-type", content_type],
                [b"content-length", str(len(content)).encode()],
                *([[b"www-authenticate", b"negotiate"]] if www_auth_header else []),
            ],
        },
        {
            "type": "http.response.body",
            "body": content,
        },
    ]


def return_false(*args, **kwargs):
    return False


@pytest.mark.asyncio
async def test_authentication_missing_but_not_required(mocker):
    """
    Ensure that when a user's auth_required_callback returns False,
    and the request is missing an auth token,
    authentication is not performed.
    """
    do_auth = mocker.patch("asgi_sspi.SPNEGOAuthMiddleware._gssapi_authenticate")

    async with TestClient(SPNEGOAuthMiddleware(index, service="http", auth_required_callback=return_false)) as app:
        r = await app.get("/")
        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert r.headers.get("WWW-Authenticate") is None

        do_auth.assert_not_called()


@pytest.mark.asyncio
async def test_authentication_invalid_but_not_required(unsuccessful_auth):
    """
    Ensure that when a user's auth_required_callback returns False,
    and the request includes an invalid auth token,
    the invalid auth is ignored and the request
    is allowed through to the app.
    """
    step, decode = unsuccessful_auth

    decode.return_value = CLIENT_TOKEN
    async with TestClient(
        SPNEGOAuthMiddleware(
            index,
            service_principal="http@example.org",
            auth_required_callback=return_false,
        )
    ) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})
        assert r.status_code == 200
        assert r.content == b"Hello ANONYMOUS"
        assert "WWW-Authenticate" not in r.headers

        step.assert_called()


@pytest.mark.asyncio
async def test_authentication_valid_but_not_required(successful_auth):
    """
    Ensure that when a users auth_required_callback returns False,
    but the request does include a valid auth token,
    the authenticated user is passed through to the app.
    """
    step, decode = successful_auth

    decode.return_value = CLIENT_TOKEN
    step.return_value = SERVER_TOKEN
    async with TestClient(
        SPNEGOAuthMiddleware(
            index,
            service="http",
            auth_required_callback=return_false,
        )
    ) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})
        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == f"Negotiate {ENCODED_SERVER_TOKEN}"

        step.assert_called()


@pytest.mark.asyncio
async def test_unauthorized():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"Unauthorized"
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_when_missing_negotiate():
    """
    Ensure that when the client sends an Authorization header that does
    not start with "Negotiate ", they receive a 401 Unauthorized response
    with a "WWW-Authenticate: Negotiate" header.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": "foo"})

        assert r.status_code == 401
        print(r.content, type(r.content))
        assert r.content.startswith(b"Unauthorized")
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_custom():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication. If configured, they should also receive customized
    content.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http", unauthorized="CUSTOM")) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"CUSTOM"
        assert r.headers["www-authenticate"] == "Negotiate"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_unauthorized_custom_content_type():
    """
    Ensure that when the client does not send an authorization token, they
    receive a 401 Unauthorized response which includes a www-authenticate
    header field which indicates the server supports Negotiate
    authentication. If configured, they should also receive customized
    content and content type.
    """
    async with TestClient(
        SPNEGOAuthMiddleware(index, service="http", unauthorized=quick_error(401, b"401!", b"text/html", True))
    ) as app:
        r = await app.get("/")

        assert r.status_code == 401
        assert r.content == b"401!"
        assert r.headers["www-authenticate"].lower() == "negotiate"
        assert r.headers["content-type"] == "text/html"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_authorized(successful_auth):
    """
    Ensure that when the client sends a correct authorization token,
    they receive a 200 OK response and the user principal is extracted and
    passed on to the routed method.
    """
    step, decode = successful_auth

    decode.return_value = CLIENT_TOKEN
    step.return_value = SERVER_TOKEN

    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})

        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == f"Negotiate {ENCODED_SERVER_TOKEN}"

        step.assert_called()


@pytest.mark.asyncio
async def test_authorized_any_hostname(successful_auth):
    """
    Ensure that the server can find matching hostname entry from the keytab.
    We set hostname="" in this test to achieve this.
    """
    step, decode = successful_auth

    decode.return_value = CLIENT_TOKEN
    step.return_value = SERVER_TOKEN

    async with TestClient(SPNEGOAuthMiddleware(index, service="http", hostname="")) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})

        assert r.status_code == 200
        assert r.content == b"Hello user@EXAMPLE.ORG"
        assert r.headers["WWW-Authenticate"] == f"Negotiate {ENCODED_SERVER_TOKEN}"

        step.assert_called()


@pytest.mark.asyncio
async def test_forbidden():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http")) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})

        assert r.status_code == 403
        assert r.content, b"Forbidden"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_forbidden_custom():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response. If configured, they should
    receive customized content.
    """
    async with TestClient(SPNEGOAuthMiddleware(index, service="http", forbidden="CUSTOM")) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})

        assert r.status_code == 403
        assert r.content == b"CUSTOM"
        assert r.headers["content-type"] == "text/plain"
        assert r.headers["content-length"] == str(len(r.content))


@pytest.mark.asyncio
async def test_forbidden_custom_content_type():
    """
    Ensure that when the client sends an incorrect authorization token,
    they receive a 403 Forbidden response. If configured, they should
    receive customized content and content-type.
    """
    async with TestClient(
        SPNEGOAuthMiddleware(index, service="http", forbidden=quick_error(403, b"CUSTOM", b"text/html"))
    ) as app:
        r = await app.get("/", headers={"Authorization": f"Negotiate {CLIENT_TOKEN}"})

        assert r.status_code == 403
        assert r.content == b"CUSTOM"
        assert r.headers["content-type"] == "text/html"
        assert r.headers["content-length"] == str(len(r.content))
