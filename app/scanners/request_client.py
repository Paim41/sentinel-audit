import time
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from app.scanners.url_validator import URLValidationError, validate_url


class RequestClientError(RuntimeError):
    pass


@dataclass
class LimitedResponse:
    response: requests.Response
    body: bytes
    redirect_chain: list[str]
    elapsed_seconds: float


class SafeRequestClient:
    user_agent = "SentinelAudit/1.0 Educational Security Auditor"

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent, "Accept": "text/html,*/*;q=0.7"})

    def request(self, url, method="GET", read_body=True):
        current_url = url
        redirects = []
        max_redirects = int(self.config.get("MAX_REDIRECTS", 3))
        timeout = (
            int(self.config.get("REQUEST_CONNECT_TIMEOUT", 5)),
            int(self.config.get("REQUEST_READ_TIMEOUT", 10)),
        )
        max_bytes = int(self.config.get("MAX_RESPONSE_BYTES", 2 * 1024 * 1024))
        started = time.perf_counter()

        for _ in range(max_redirects + 1):
            validate_url(current_url, self.config)
            try:
                response = self.session.request(
                    method,
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.exceptions.SSLError as exc:
                raise RequestClientError("TLS verification failed for the target.") from exc
            except requests.exceptions.ConnectTimeout as exc:
                raise RequestClientError("Connection timed out while contacting the target.") from exc
            except requests.exceptions.ReadTimeout as exc:
                raise RequestClientError("Read timed out while receiving the target response.") from exc
            except requests.exceptions.TooManyRedirects as exc:
                raise RequestClientError("Too many redirects were encountered.") from exc
            except requests.RequestException as exc:
                raise RequestClientError(f"Unable to request the target: {exc}") from exc

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                redirects.append(next_url)
                if len(redirects) > max_redirects:
                    raise RequestClientError("The target exceeded the maximum redirect limit.")
                current_url = next_url
                response.close()
                continue

            body = b""
            if read_body and method.upper() != "HEAD":
                try:
                    for chunk in response.iter_content(chunk_size=16384):
                        if not chunk:
                            continue
                        body += chunk
                        if len(body) > max_bytes:
                            raise RequestClientError("The target response exceeded the configured size limit.")
                finally:
                    response.close()
            elapsed = time.perf_counter() - started
            return LimitedResponse(response, body, redirects, elapsed)

        raise RequestClientError("The redirect chain could not be resolved safely.")

    def head_or_small_get(self, url):
        try:
            return self.request(url, method="HEAD", read_body=False)
        except RequestClientError:
            return self.request(url, method="GET", read_body=True)
