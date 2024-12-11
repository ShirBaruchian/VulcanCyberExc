class RuleProcessor:
    OPERATORS = {
        "eq": lambda x, y: x == y,
        "gt": lambda x, y: float(x) > float(y),
        "lt": lambda x, y: float(x) < float(y),
    }

    @staticmethod
    def parse_rules(raw_rules):
        """Parses raw rules into a structured format."""
        parsed_rules = []
        for rule in raw_rules:
            parsed_rules.append({
                "type": rule["type"],
                "parameter": rule["parameter"],
                "operator": RuleProcessor.OPERATORS[rule["operator"]],
                "value": rule["value"]
            })
        return parsed_rules
