from dataclasses import dataclass
from .address import Address
from .transaction_data import TransactionData


@dataclass
class Transaction:
    address: Address
    type: str
    version: int = 1
    chain_length: int = 0
    originSignature: str = ""
    previousPublicKey: str = ""
    previousSignature: str = ""
    data: TransactionData = TransactionData()






