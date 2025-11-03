from typing import List

class RAGEngine:
    """
    RAG Top-K 근거 추출 모듈 (PoC 버전)
    """
    def __init__(self):
        self.docs = [
            "Spring4Shell 취약점은 CVE-2022-22965로 알려진 Java Framework 취약점이다.",
            "HeartBleed은 TLS heartbeat 요청 길이 조작을 통해 메모리 누출을 유발한다."
        ]

    def retrieve(self, query: str, top_k: int = 2) -> List[str]:
        # 단순 문자열 유사도 기반 dummy 검색
        return [doc for doc in self.docs if query.lower() in doc.lower()][:top_k]
