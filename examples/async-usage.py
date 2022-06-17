'''
This Source Code Form is subject to the terms of the
Mozilla Public License, v. 2.0. If a copy of the MPL
was not distributed with this file, You can obtain one
at http://mozilla.org/MPL/2.0/.
'''


import asyncio
import ignition


async def run():
  response = await ignition.request_async('//station.martinrue.com')

  # response.body is an asyncio.StreamReader
  print(await response.body.readline())

  print(await response.body.read())


loop = asyncio.get_event_loop()
loop.run_until_complete(run())
