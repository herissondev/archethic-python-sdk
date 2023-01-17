from dataclasses import dataclass


@dataclass
class Address:
    address: str
    
    def __str__(self):
        return self.address

    def __repr__(self):
        return self.address

    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)
