import ssl
import asyncio
import logging

from .protocol import GeminiProtocolAsync
from ..request import Request
from ..ssl.cert_wrapper import CertWrapper


logger = logging.getLogger(__name__)


class AsyncRequest(Request):
  cert_wrapper: CertWrapper
  transport: asyncio.Transport
  _ssl_socket: ssl.SSLObject

  def start(self) -> None:
    encoded_url = str(self._url).encode('utf-8')
    self.transport.write(b"%s\r\n" % (encoded_url,))

  async def send(self):
    loop = asyncio.get_running_loop()
    assert loop, 'You need a running asyncio event loop to send a request'

    protocol = GeminiProtocolAsync(self, loop=loop)

    transport, _proto = await loop.create_connection(
      lambda: protocol,
      self._url.host(),
      self._url.port(),
      server_hostname=self._url.host(),
      ssl=self._setup_ssl_default_context()
    )

    sslctx = transport.get_extra_info('sslcontext')
    self._ssl_socket = transport.get_extra_info('socket')

    try:
      if self.is_using_ca_cert():
        self._setup_ssl_client_certificate_context(sslctx)

      ssl_certificate_result = self._validate_ssl_certificate(
        transport._ssl_protocol._extra['ssl_object']
      )
      assert ssl_certificate_result.certificate, 'Invalid certificate'

      self.cert_wrapper = ssl_certificate_result
    except Exception as err:
      logger.warning(f"SSL negotiation error for {self._url.host()} - {err}")
      return None

    return await protocol.response
