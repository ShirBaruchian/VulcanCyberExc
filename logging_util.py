import aiofiles


async def log_alerts(alerts_stream, log_file):
    async with aiofiles.open(log_file, mode="a") as file:
        async for alert in alerts_stream:
            message = (
                f"vulnerability {alert['vulnerability_name']} with risk {alert['risk']} "
                f"discovered on {alert['hostname']} {alert['ip']}\n"
            )
            await file.write(message)
