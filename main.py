import asyncio
from data_fetcher import DataFetcher
from rule_processor import RuleProcessor
from detection import DetectionEngine
from logging_util import log_alerts

async def main():
    try:
        servers_stream = DataFetcher.fetch_servers()
        vulnerabilities_stream = DataFetcher.fetch_vulnerabilities(start_id=1, batch_size=10)
        rules_stream = DataFetcher.fetch_rules("./rules.csv")

        rules = [rule async for rule in rules_stream]
        parsed_rules = RuleProcessor.parse_rules(rules)

        detections_stream = DetectionEngine.process_pipeline(servers_stream, vulnerabilities_stream, parsed_rules)

        log_file = "./detections.log"
        await log_alerts(detections_stream, log_file)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())