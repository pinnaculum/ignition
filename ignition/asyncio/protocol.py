from __future__ import annotations

import logging
import asyncio
import re
from typing import Optional

from ..exceptions import GeminiResponseParseError
from ..request import GEMINI_RESPONSE_HEADER_SEPARATOR
from ..globals import GEMINI_MAXIMUM_BODY_SIZE
from ..response import BaseResponse


logger = logging.getLogger(__name__)


class AsyncResponse(BaseResponse):
  stream: Optional[asyncio.StreamReader]

  @property
  def body(self):
    return self.stream


class ResponseParser:
  """
  Derived from keis/aiogemini (aiogemini.client.protocol.ResponseParser)
  """

  buffer: Optional[bytes] = bytes()
  stream: Optional[asyncio.StreamReader] = None

  def __init__(self):
    self.response = None

  def feed_data(self, data: bytes) -> None:
    if self.response:
        self.response.stream.feed_data(data)
        return

    self.buffer += data
    try:
      headerend = self.buffer.index(b'\r\n')
    except ValueError:
      return None

    header = self.buffer[:headerend].decode('utf-8')
    status, meta = re.split(GEMINI_RESPONSE_HEADER_SEPARATOR, header, maxsplit=1)

    if not re.match(r"^\d{2}$", status):
        raise GeminiResponseParseError("Response status is not a two-digit code")

    stream = asyncio.StreamReader(limit=GEMINI_MAXIMUM_BODY_SIZE)
    stream.set_transport(self.request.transport)

    self.response = AsyncResponse(
      self.request._url,
      status,
      meta,
      None,  # empty raw body, we use the StreamReader
      self.request.cert_wrapper.certificate
    )

    self.response.stream = stream

    stream.feed_data(self.buffer[headerend+2:])

  def feed_eof(self) -> None:
    if self.response:
      self.response.stream.feed_eof()
    else:
      raise Exception('Trying to feed EOF with no response')


class GeminiProtocolAsync(asyncio.Protocol):
  _loop: asyncio.AbstractEventLoop
  _parser: ResponseParser

  response: asyncio.Future[AsyncResponse]

  def __init__(
    self,
    request,
    *,
    loop: asyncio.AbstractEventLoop
  ) -> None:
    self._loop = loop
    self._parser = ResponseParser()
    self._parser.request = request
    self.request = request
    self.response = loop.create_future()

  def connection_made(self, transport: asyncio.Transport) -> None:
    self.request.transport = transport
    self.request.start()

  def connection_lost(self, exc) -> None:
    try:
      self._parser.feed_eof()
    except Exception as err:
      logger.warning(f'Failed to feed EOF after losing connection: {err}')

  def data_received(self, data: bytes) -> None:
    self._parser.feed_data(data)

    if self._parser.response and not self.response.done():
        self.response.set_result(self._parser.response)
