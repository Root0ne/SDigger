import asyncio
import logging

from .subdomain_discovery import SubdomainDiscovery

async def run_discovery(
    subdomain_discovery: SubdomainDiscovery,
    update_queue: asyncio.Queue
):
    def log_callback(message):
        logging.info(message)

    def progress_callback(current, total):
        progress = current / total
        asyncio.run_coroutine_threadsafe(
            update_queue.put({
                "type": "progress",
                "progress": progress,
                "text": f"Progress: {current}/{total}",
                "lines_tried": current
            }),
            asyncio.get_event_loop()
        )

    async def subdomain_callback(
        subdomain, ip_addresses, result=None, ssl_analysis=False, org_info=None
    ):
        data = {
            "type": "subdomain",
            "subdomain": subdomain,
            "ip_addresses": ip_addresses,
            "result": result,
            "ssl_analysis": ssl_analysis,
            "org_info": org_info
        }
        await update_queue.put(data)

    try:
        await subdomain_discovery.run(log_callback, progress_callback, subdomain_callback)
    except asyncio.CancelledError:
        log_callback("Discovery task was cancelled.")
    finally:
        await update_queue.put({"type": "done"})
