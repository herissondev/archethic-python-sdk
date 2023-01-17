from typing import List, Optional
from ..api import Api
from .transaction import Transaction

# TODO: add functionallity to get the transaction chain directly from the TransactionChain class


class TransactionChain:
    def __init__(self, transactions: List[Transaction]):
        self.transactions = transactions




