import asyncio, resource, sys
resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
async def handle(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except Exception:
        pass
    w.close()
async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[1]), backlog=8192)
    async with srv:
        await srv.serve_forever()
asyncio.run(main())
