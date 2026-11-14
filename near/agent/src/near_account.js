// near-api-js account for one key: the agent's function-call key, or the attester's key.
import nearApi from 'near-api-js';

const { connect, keyStores, KeyPair } = nearApi;

/** {account, keyPair} signing as accountId with secretKey ("ed25519:..."). near-api-js logging is off. */
export async function connectAccount({ nodeUrl, networkId, accountId, secretKey }) {
  const keyPair = KeyPair.fromString(secretKey);
  const keyStore = new keyStores.InMemoryKeyStore();
  await keyStore.setKey(networkId, accountId, keyPair);
  const near = await connect({ networkId, nodeUrl, keyStore, logger: false });
  return { account: await near.account(accountId), keyPair };
}
