from abc import ABC, abstractmethod

class Report(ABC):
    @abstractmethod
    def add_entry(self, vuln_type: str, url: str, param: str, payload: str, evidence: str):
        pass

    @abstractmethod
    def generate(self) -> str:
        pass

    @abstractmethod
    def save(self, filepath: str):
        pass
