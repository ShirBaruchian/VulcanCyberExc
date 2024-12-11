import logging

class DetectionEngine:
    @staticmethod
    def is_match(entity, rule):
        value = entity.get(rule["parameter"])
        if value is None:
            return False
        return rule["operator"](value, rule["value"])

    @staticmethod
    def evaluate_server_rules(server, rules):
        for rule in rules:
            if rule["type"] == "server" and not DetectionEngine.is_match(server, rule):
                return False
        return True

    @staticmethod
    def evaluate_vulnerability_rules(vulnerability, rules):
        for rule in rules:
            if rule["type"] == "vulnerability" and not DetectionEngine.is_match(vulnerability, rule):
                return False
        return True

    @staticmethod
    async def process_pipeline(servers_stream, vulnerabilities_stream, rules):
        server_rules = [rule for rule in rules if rule["type"] == "server" ]
        vulnerability_rules = [rule for rule in rules if rule["type"] == "vulnerability"]

        async for server in servers_stream:
            if not DetectionEngine.evaluate_server_rules(server, server_rules):
                continue

            async for vulnerability in vulnerabilities_stream:
                if "affects" not in vulnerability:
                    logging.warning(f"invalid vulnerability: {vulnerability}")

                if "affects" not in vulnerability or server["os"] + "_" + server["osVersion"] == vulnerability["affects"]:
                    if DetectionEngine.evaluate_vulnerability_rules(vulnerability, vulnerability_rules):
                        yield {
                            "vulnerability_name": vulnerability["name"],
                            "risk": vulnerability["risk"],
                            "hostname": server["hostname"],
                            "ip": server["ip"],
                        }
