import asyncio

class GlobalQueues:
    def __init__(self):
        # Ingest -> Detect
        self.detect_queue: asyncio.Queue = asyncio.Queue()
        # Detect -> LLM
        self.llm_queue: asyncio.Queue = asyncio.Queue()

queues = GlobalQueues()