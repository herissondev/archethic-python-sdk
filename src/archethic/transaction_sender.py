
from archethic.transaction_builder import TransactionBuilder
from asyncio.events import Handle
class TransactionHandler:
    events = ['']
    def __init__(self, api):
        self.on_confirmation = []
        self.confirmation_notifier: Handle = None
        self.api = api

    def on(self, event, function):

        if event == "confirmation" :
            self.on_confirmation.append(function)

    async def send(self, tx: TransactionBuilder):

        tx_address = tx.address.hex()
        self.confirmation_notifier = self.api.wait_confirmation(tx_address, self.handle_confirmation)
        result = await self.api.send_transaction(tx)

    def handle_confirmation(self, nb_confirmations, max_confirmations):
        for func in self.on_confirmation:
            print(nb_confirmations)
            print(max_confirmations)

        if nb_confirmations == max_confirmations:
            self.confirmation_notifier.cancel()
