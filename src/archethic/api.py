import aiohttp
from typing import Union, Callable
from urllib.parse import urlparse
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.phoenix_channel_websockets import PhoenixChannelWebsocketsTransport
from gql.transport.exceptions import TransportQueryError

from archethic.transaction_builder import TransactionBuilder
from archethic.keychain import Keychain
from archethic.crypto import derive_address, derive_keypair, verify, ec_decrypt, aes_decrypt
from archethic.transaction_sender import TransactionHandler
import requests

class Api:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

        parse = urlparse(endpoint)

        if parse.scheme == 'http':
            ws_endpoint = 'ws://' + parse.netloc + "/socket/websocket"
            self.graphql_ws_client = Client(
                transport=PhoenixChannelWebsocketsTransport(
                    url=ws_endpoint
                )
            )

        elif parse.scheme == 'https':
            ws_endpoint = 'wss://' + parse.netloc + "/socket/websocket"
            self.graphql_ws_client = Client(
                transport=PhoenixChannelWebsocketsTransport(
                    url=ws_endpoint
                )
            )
        print(self.graphql_ws_client.fetch_schema_from_transport)
        self.graphql_http_client = Client(
            transport=AIOHTTPTransport(
                url=self.endpoint + "/api"
            )
        )

        self.session = aiohttp.ClientSession()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    async def send_transaction(self, tx: TransactionBuilder):
        url = self.endpoint + '/api/transaction'
        data = tx.json()
        try:
            resp = await self.session.post(url, data=data)
            resp.raise_for_status()
            return await resp.json()

        except Exception as e:
            raise e


    async def get_transaction_index(self, address: str) -> int:
        query = 'query {lastTransaction(address: "%s") {chainLength}}' % address
        query = gql(query)
        try:
            response = await self.graphql_http_client.execute_async(query)
            return response['lastTransaction']['chainLength']
        except TransportQueryError as e:
            return 0

    async def get_transaction_fee(self, tx: TransactionBuilder):
        url = self.endpoint + '/api/transaction_fee'
        data = tx.json()
        try:
            resp = await self.session.post(url, data=data)
            resp.raise_for_status()
            return await resp.json()

        except requests.exceptions.HTTPError as e:
            raise e

    # TODO : implement wait_confirmation, wss seems to be blocked ?
    async def wait_confirmation(self, address: str, handler: callable):

        sub = 'subscription {transactionConfirmed (address: "%s") {address maxConfirmations nbConfirmations}}' % address
        sub = gql(sub)

        async for result in self.graphql_ws_client.subscribe_async(sub):
            max_confirmation = result.get('transactionConfirmed').get('maxConfirmations')
            nb_confirmations = result.get('transactionConfirmed').get('nbConfirmations')
            handler(nb_confirmations, max_confirmation)

    async def wait_error(self, address: str, handler: callable):

        sub = 'subscription {transactionError (address: "%s") {context reason}}' % address
        sub = gql(sub)

        async for result in self.graphql_ws_client.subscribe_async(sub):
            context = result.get('transactionError').get('context')
            reason = result.get('transactionError').get('reason')
            handler(context, reason)

    async def get_transaction_ownerships(self, address: str):
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
            response = await self.graphql_http_client.execute_async(query)
            return response['transaction']['data']['ownerships']
        except TransportQueryError as e:
            return []

    async def get_keychain(self, seed: Union[str, bytes]):
        access_private_key, access_public_key = derive_keypair(seed, 0)
        access_keychain_address = derive_address(seed, 1)

        ownerships = await self.get_transaction_ownerships(access_keychain_address)
        if len(ownerships) == 0:
            raise Exception("Keychain doesn't exist!")

        secret, public_keys = ownerships[0]['secret'], ownerships[0]['authorizedPublicKeys']

        encrypted_secret_key = [p['encryptedSecretKey'] for p in public_keys if p['publicKey'].upper() == access_public_key.upper()][0]

        aes_key = ec_decrypt(encrypted_secret_key, access_private_key)
        keychain_address = aes_decrypt(secret, aes_key)

        ownerships = self.get_transaction_ownerships(keychain_address.hex())
        secret, public_keys = ownerships[0]['secret'], ownerships[0]['authorizedPublicKeys']

        encrypted_secret_key = [p['encryptedSecretKey'] for p in public_keys if p['publicKey'].upper() == access_public_key.upper()][0]
        aes_key = ec_decrypt(encrypted_secret_key, access_private_key)
        keychain_binary = aes_decrypt(secret, aes_key)

        return Keychain.from_binary(keychain_binary)

    def create_transaction_handler(self):
        return TransactionHandler(self)








