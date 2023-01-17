

class Address:
    def __init__(self, address: str):
        """
        The Address class represents a transaction's address
        """
        self.address = address

    def __str__(self):
        return self.address

    def __repr__(self):
        return self.address

    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)
