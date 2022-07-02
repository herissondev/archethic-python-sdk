import json
from pprint import pprint
from archethic.transaction_builder import TransactionBuilder
import requests
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.exceptions import TransportQueryError


class Api:
    def __init__(self, endpoint: str):

        _transport = RequestsHTTPTransport(url=endpoint + "/api")
        self.endpoint = endpoint
        self.client = Client(transport=_transport)
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    def send_tx(self, tx: TransactionBuilder):
        url = self.endpoint + '/api/transaction'
        data = tx.json()
        print(data)
        resp = self.session.post(url, data=data)
        print(resp.text)
        print(resp.status_code)
        return resp


    def get_transaction_index(self, address: str) -> int:
        query = 'query {lastTransaction(address: "%s") {chainLength}}' % address
        query = gql(query)
        try:
            response = self.client.execute(query)
            print(response)
            return response['lastTransaction']['chainLength']
        except TransportQueryError as e:
            return 0

