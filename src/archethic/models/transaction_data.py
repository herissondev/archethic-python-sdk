from dataclasses import dataclass, field

@dataclass
class TransactionData:
    content: str = ""
    code: str = ""
    ledger: list = field(default_factory=list)
    ownerships: list = field(default_factory=list)
    recipients: list = field(default_factory=list)
