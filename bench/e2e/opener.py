# Opens N connections, does one 32KB echo round trip on each, then
# holds them idle until stdin closes.
import asyncio, resource, sys
resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
async def one(port, conns):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"x" * 32768)
    await w.drain()
    await r.readexactly(32768)
    conns.append(w)
async def main():
    port, n = int(sys.argv[1]), int(sys.argv[2])
    conns = []
    sem = asyncio.Semaphore(200)
    async def guarded():
        async with sem:
            await one(port, conns)
    res = await asyncio.gather(*(guarded() for _ in range(n)), return_exceptions=True)
    errs = [e for e in res if isinstance(e, Exception)]
    print(f"open {len(conns)} errors {len(errs)} {errs[:1]}", flush=True)
    await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
asyncio.run(main())
