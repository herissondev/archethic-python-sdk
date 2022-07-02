from archethic.transaction_builder import TransactionBuilder
import requests
from urllib.parse import urlparse
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.websockets import WebsocketsTransport
from gql.transport.exceptions import TransportQueryError


class Api:
    def __init__(self, endpoint: str):
        parse = urlparse(endpoint)

        if parse.scheme == 'http':
            ws_endpoint = 'ws://' + parse.netloc + "/socket"
            self.ws_client = Client(
                transport=WebsocketsTransport(
                    url=ws_endpoint,


                )
            )
        elif parse.scheme == 'https':
            ws_endpoint = 'wss://' + parse.netloc + "/socket"
            self.ws_client = Client(
                transport=WebsocketsTransport(
                    url=ws_endpoint,
                )
            )

        _transport = RequestsHTTPTransport(url=endpoint + "/api")
        self.endpoint = endpoint
        self.client = Client(transport=_transport)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    def send_tx(self, tx: TransactionBuilder):
        url = self.endpoint + '/api/transaction'
        data = tx.json()
        try:
            resp = self.session.post(url, data=data)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            raise e

    def get_transaction_index(self, address: str) -> int:
        query = 'query {lastTransaction(address: "%s") {chainLength}}' % address
        query = gql(query)
        try:
            response = self.client.execute(query)
            return response['lastTransaction']['chainLength']
        except TransportQueryError as e:
            return 0

    def get_transaction_fee(self, tx: TransactionBuilder):
        url = self.endpoint + '/api/transaction_fee'
        data = tx.json()
        try:
            resp = self.session.post(url, data=data)
            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.HTTPError as e:
            raise e

    # TODO : implement wait_confirmation, wss seems to be blocked ?
    def wait_confirmation(self, address: str):
        raise NotImplementedError('wait_confirmation is not implemented yet')
        sub = 'subscription {transactionConfirmed(address: "%s") {nbConfirmations}}' % address
        sub = gql(sub)

    def get_transaction_ownerships(self, address: str):
        query = '''query {
                    transaction(address: "%s") {
                      data {
                        ownerships {
                          secret,
                          authorizedPublicKeys {
                            encryptedSecretKey,
                            publicKey
                          }
                        }
                      }
                    }
                }''' % address
        query = gql(query)
        try:
            response = self.client.execute(query)
            return response['transaction']['data']['ownerships']
        except TransportQueryError as e:
            return []






