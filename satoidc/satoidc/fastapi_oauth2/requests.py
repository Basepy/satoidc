import json
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Optional
from urllib.parse import parse_qs

from authlib.oauth2.rfc6749 import (
    JsonPayload,
    JsonRequest,
    OAuth2Payload,
    OAuth2Request,
)
from starlette.requests import Request


def _decode_cached_body(request: Request) -> bytes:
    """Lê o body já cacheado pelo Starlette. Sync.
    Retorna b'' se ainda não foi lido (ou seja, não cacheou).
    """
    body = getattr(request, "_body", None)
    return body or b""


def _is_form_urlencoded(request: Request) -> bool:
    ct = (request.headers.get("content-type") or "").lower()
    return "application/x-www-form-urlencoded" in ct


def _is_json(request: Request) -> bool:
    ct = (request.headers.get("content-type") or "").lower()
    return "application/json" in ct or ct.endswith("+json")


def _parse_cached_form(request: Request) -> Dict[str, Any]:
    """Parseia x-www-form-urlencoded a partir de request._body (se existir)."""
    body = _decode_cached_body(request)
    if not body or not _is_form_urlencoded(request):
        return {}

    qs = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    # flatten: 1 valor vira escalar, >1 vira lista
    out: Dict[str, Any] = {}
    for k, v in qs.items():
        if not v:
            continue
        out[k] = v[0] if len(v) == 1 else v
    return out


def _parse_cached_json(request: Request) -> Dict[str, Any]:
    """Parseia JSON a partir de request._body (se existir)."""
    body = _decode_cached_body(request)
    if not body or not _is_json(request):
        return {}
    try:
        obj = json.loads(body.decode("utf-8"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


class FastAPIOAuth2Payload(OAuth2Payload):
    """
    Payload 100% sync.

    Fonte de dados:
      1) query params (sempre)
      2) body cacheado (request._body) se existir:
         - x-www-form-urlencoded
         - json (fallback)
    """

    def __init__(self, request: Request):
        self._request = request
        self._data: Optional[Dict[str, Any]] = None
        self._datalist: Optional[DefaultDict[str, List[Any]]] = None
        self._load()

    def _load(self) -> None:
        # query params
        qp = self._request.query_params

        data: Dict[str, Any] = {}
        datalist: DefaultDict[str, List[Any]] = defaultdict(list)

        for k in qp.keys():
            values = qp.getlist(k)
            if values:
                data[k] = values[0]
                datalist[k].extend(values)

        # body cacheado (se houver)
        if self._request.method.upper() != "GET":
            body_data = _parse_cached_form(self._request)
            if not body_data:
                body_data = _parse_cached_json(self._request)

            # body "ganha" da query
            for k, v in body_data.items():
                if isinstance(v, list):
                    datalist[k] = list(v)
                    data[k] = v[0] if v else None
                else:
                    datalist[k] = [v]
                    data[k] = v

        self._data = data
        self._datalist = datalist

    @property
    def data(self):
        return self._data or {}

    @property
    def datalist(self):
        return self._datalist or defaultdict(list)


class FastAPIOAuth2Request(OAuth2Request):
    """Equivalente ao FlaskOAuth2Request, 100% sync."""

    def __init__(self, request: Request):
        super().__init__(
            method=request.method,
            uri=str(request.url),
            # Headers do Starlette ignora maiúsculas/minúsculas; o authlib procura
            # "Authorization" (client_secret_basic) com essa grafia exata.
            headers=request.headers,
        )
        self._request = request
        self.payload = FastAPIOAuth2Payload(request)

    @property
    def args(self):
        return self._request.query_params

    @property
    def form(self):
        return self.payload.data

    @property
    def data(self):
        # algumas partes antigas do authlib usam request.data
        return self.payload.data

    @property
    def datalist(self):
        return self.payload.datalist


class FastAPIJsonPayload(JsonPayload):
    """Payload JSON 100% sync baseado no body cacheado (request._body)."""

    def __init__(self, request: Request):
        self._request = request
        self._data = _parse_cached_json(request)

    @property
    def data(self):
        return self._data


class FastAPIJsonRequest(JsonRequest):
    """Equivalente ao FlaskJsonRequest, 100% sync."""

    def __init__(self, request: Request):
        super().__init__(
            request.method, str(request.url), request.headers
        )
        self.payload = FastAPIJsonPayload(request)
