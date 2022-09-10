from archethic.transaction_builder import TransactionBuilder
from archethic.keychain import Keychain
from archethic.crypto import derive_address, derive_keypair, ec_decrypt, aes_decrypt
import requests
from typing import Union
from urllib.parse import urlparse
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.websockets import WebsocketsTransport
from gql.transport.exceptions import TransportQueryError


class Api:
    def __init__(self, endpoint: str):
        parse = urlparse(endpoint)

        if parse.scheme == "http":
            ws_endpoint = "ws://" + parse.netloc + "/socket"
            self.ws_client = Client(
                transport=WebsocketsTransport(
                    url=ws_endpoint,
                )
            )
        elif parse.scheme == "https":
            ws_endpoint = "wss://" + parse.netloc + "/socket"
            self.ws_client = Client(
                transport=WebsocketsTransport(
                    url=ws_endpoint,
                )
            )

        _transport = RequestsHTTPTransport(url=endpoint + "/api")
        self.endpoint = endpoint
        self.client = Client(transport=_transport)
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    def send_tx(self, tx: TransactionBuilder):
        url = self.endpoint + "/api/transaction"
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
            return response["lastTransaction"]["chainLength"]
        except TransportQueryError as e:
            return 0

    def get_transaction_fee(self, tx: TransactionBuilder):
        url = self.endpoint + "/api/transaction_fee"
        data = tx.json()
        try:
            resp = self.session.post(url, data=data)
            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.HTTPError as e:
            raise e

    def get_storage_nonce_public_key(self) -> str:
        """
        Retrieve the storage nonce public key to encrypt data towards nodes
        :return:
        """
        query = """query {
                    sharedSecrets {
                        storageNoncePublicKey
                    }
                }"""
        query = gql(query)
        try:
            response = self.client.execute(query)
            return response["sharedSecrets"]["storageNoncePublicKey"]
        except TransportQueryError as e:
            return ""

    # TODO : implement wait_confirmation, wss seems to be blocked ?
    def wait_confirmation(self, address: str):
        raise NotImplementedError("wait_confirmation is not implemented yet")
        sub = (
            'subscription {transactionConfirmed(address: "%s") {nbConfirmations}}'
            % address
        )
        sub = gql(sub)

    def get_transaction_ownerships(self, address: str):
        query = (
            """query {
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
                }"""
            % address
        )
        query = gql(query)
        try:
            response = self.client.execute(query)
            return response["transaction"]["data"]["ownerships"]
        except TransportQueryError as e:
            return []

    def get_keychain(self, seed: Union[str, bytes]) -> Keychain:
        """
        Retrieve a keychain from the keychain access transaction and decrypt the wallet to retrieve the services associated
        :param seed: Keychain access's seed
        :return: Keychain instance
        """
        access_private_key, access_public_key = derive_keypair(seed, 0)
        access_keychain_address = derive_address(seed, 1)

        ownerships = self.get_transaction_ownerships(access_keychain_address)
        if len(ownerships) == 0:
            raise Exception("Keychain doesn't exist!")

        secret, public_keys = (
            ownerships[0]["secret"],
            ownerships[0]["authorizedPublicKeys"],
        )

        encrypted_secret_key = [
            p["encryptedSecretKey"]
            for p in public_keys
            if p["publicKey"].upper() == access_public_key.upper()
        ][0]

        aes_key = ec_decrypt(encrypted_secret_key, access_private_key)
        keychain_address = aes_decrypt(secret, aes_key)

        ownerships = self.get_transaction_ownerships(keychain_address.hex())
        secret, public_keys = (
            ownerships[0]["secret"],
            ownerships[0]["authorizedPublicKeys"],
        )

        encrypted_secret_key = [
            p["encryptedSecretKey"]
            for p in public_keys
            if p["publicKey"].upper() == access_public_key.upper()
        ][0]
        aes_key = ec_decrypt(encrypted_secret_key, access_private_key)
        keychain_binary = aes_decrypt(secret, aes_key)

        return Keychain.from_binary(keychain_binary)
