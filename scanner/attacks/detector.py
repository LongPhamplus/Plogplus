
from abc import ABC, abstractmethod

from scanner.core.payload import PayloadInfo


class Detector(ABC):
    """
    Base class cho tất cả các lớp phát hiện lỗ hổng
    """

    @abstractmethod
    async def detect(
            self,
            response,
            payload_info: PayloadInfo
    ):
        """
        Trả về True nếu response cho thấy có dấu hiệu bị khai thác.
        """
        raise NotImplementedError("Override me please")