export interface UserModel {
  id: string;
  username: string;
  authenticators: Authenticator[];
  challenge: string;
}

export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

export type AuthenticatorTransport = 'usb' | 'ble' | 'nfc' | 'internal';
/**
 * It is strongly advised that authenticators get their own DB
 * table, ideally with a foreign key to a specific UserModel.
 *
 * "SQL" tags below are suggestions for column data types and
 * how best to store data received during registration for use
 * in subsequent authentications.
 */
export interface Authenticator {
  // SQL: Encode to base64url then store as `TEXT`. Index this column
  credentialID: Uint8Array;
  // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
  credentialPublicKey: Uint8Array;
  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  counter: number;
  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'
  credentialDeviceType: CredentialDeviceType;
  // SQL: `BOOL` or whatever similar type is supported
  credentialBackedUp: boolean;
  // SQL: `VARCHAR(255)` and store string array as a CSV string
  // Ex: ['usb' | 'ble' | 'nfc' | 'internal']
  transports?: AuthenticatorTransport[];
}

export const userTable: UserModel[] = [
  {
    id: '1234',
    username: 'Test',
    authenticators: [],
    challenge: '',
  },
  {
    id: '2345',
    username: 'Test2',
    authenticators: [],
    challenge: '',
  },
];

export const getUserData = (userId: string) => {
  return userTable.find((user) => user.id === userId);
};

export const setUserData = (user: UserModel) => {
  const index = userTable.findIndex((u) => u.id === user.id);

  if (index < 0) {
    userTable.push(user);
  }

  userTable[index] = user;
};

export const storeUserAuthenticator = (
  userId: string,
  authenticator: Authenticator
) => {
  const user = getUserData(userId);

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  user.authenticators.push(authenticator);

  setUserData(user);
};

export const storeUserChallenge = (userId: string, challenge: string) => {
  const user = getUserData(userId);

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  user.challenge = challenge;

  setUserData(user);
};
