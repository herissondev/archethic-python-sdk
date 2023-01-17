from dataclasses import dataclass
from .address import Address


@dataclass
class Token:
    genesis: Address
    name: str
    symbol: str
    supply: int
    type: str
    properties: list
    collection: str
    id: str
    decimals: int


    def __str__(self):
        return f"TOKEN: {self.name} ({self.symbol})"

    def __eq__(self, other):
        return self.id == other.id

