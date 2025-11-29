class DetectorService:
    def run_rule_detect(self, record: dict) -> dict:
        line = record.get("raw_line", "").lower()
        score = 0.0
        if "failed password" in line or "error" in line:
            score = 0.8
        return {"type": "rule", "score": score, "rule": "basic_error_check"}

    def run_ml_detect(self, record: dict) -> dict:
        return {"type": "ml", "score": 0.1, "model": "mock_v1"}

    def run_yara_detect(self, record: dict) -> dict:
        return {"type": "yara", "score": 0.0, "match": False}
        
    def aggregate(self, results: list) -> dict:
        max_score = max(r["score"] for r in results)
        return {"max_score": max_score, "details": results}