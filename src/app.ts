import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/typescript-types';
import bodyParser from 'body-parser';
import cors from 'cors';
import express, { Request } from 'express';
import {
  Authenticator,
  getUserData,
  storeUserAuthenticator,
  storeUserChallenge,
  userTable,
} from './user-db';

const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const port = 3000;

// Human-readable title for your website
const rpName = 'TNGD PASSKEY DEMO';
// A unique identifier for your website
const rpID = 'localhost';
// The URL at which registrations and authentications should occur
const origin = `http://${rpID}:10001`;

app.post(
  '/get-register-options',
  (req: Request<{}, {}, { userId: string }>, res) => {
    try {
      const { userId } = req.body;

      // retrieve the user from the database after they've logged in
      const user = getUserData(userId);

      if (!user) {
        throw new Error('USER_NOT_FOUND');
      }

      // retrieve any of the user's previously registered authenticators
      const userAuthenticators = user.authenticators;

      const options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        // don't prompt users for additional information about the authenticator, recommended for smoother UX
        attestationType: 'none',
        // prevent users from re-registering existing authenticators
        excludeCredentials: userAuthenticators.map((authenticator) => ({
          id: authenticator.credentialID,
          type: 'public-key',
          // optional
          transports: authenticator.transports,
        })),
      });

      // remember the challenge for this user
      storeUserChallenge(userId, options.challenge);

      res.send(options);
    } catch (error) {
      res.send({ errorMessage: error.message });
    }
  }
);

app.post(
  '/register-passkey',
  async (
    req: Request<{}, {}, { userId: string; body: RegistrationResponseJSON }>,
    res
  ) => {
    try {
      const { userId, body } = req.body;

      const user = getUserData(userId);
      // get `options.challenge` that was saved above
      const expectedChallenge = user?.challenge;

      if (!expectedChallenge) {
        throw new Error('MISSING_USER_CHALLENGE');
      }

      const { verified, registrationInfo } = await verifyRegistrationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });

      if (!registrationInfo) {
        throw new Error('MISSING_REGISTRATION_INFO');
      }

      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const newAuthenticator: Authenticator = {
        credentialID,
        credentialPublicKey,
        counter,
        credentialBackedUp: false,
        credentialDeviceType: 'singleDevice',
      };

      // save the authenticator info so that we can get it by user ID later
      storeUserAuthenticator(userId, newAuthenticator);

      res.json({ authenticator: newAuthenticator, verified });
    } catch (error) {
      res.send({ errorMessage: error.message });
    }
  }
);

app.post(
  '/get-authenticate-options',
  async (req: Request<{}, {}, { userId: string }>, res) => {
    try {
      const { userId } = req.body;

      // retrieve the logged-in user
      const user = getUserData(userId);

      if (!user) {
        throw new Error('USER_NOT_FOUND');
      }

      // retrieve any of the user's previously registered authenticators
      const userAuthenticators = user.authenticators;

      const options = generateAuthenticationOptions({
        // Require users to use a previously-registered authenticator
        allowCredentials: userAuthenticators.map((authenticator) => ({
          id: authenticator.credentialID,
          type: 'public-key',
          // optional
          transports: authenticator.transports,
        })),
        userVerification: 'preferred',
      });

      // remember this challenge for this user
      storeUserChallenge(userId, options.challenge);

      res.send(options);
    } catch (error) {
      res.send({ errorMessage: error.message });
    }
  }
);

app.post(
  '/authenticate-passkey',
  async (
    req: Request<{}, {}, { userId: string; body: AuthenticationResponseJSON }>,
    res
  ) => {
    try {
      const { userId, body } = req.body;

      // retrieve the logged-in user
      const user = getUserData(userId);

      if (!user) {
        throw new Error('USER_NOT_FOUND');
      }

      // get `options.challenge` that was saved above
      const expectedChallenge = user.challenge;
      // retrieve an authenticator from the DB that
      // should match the `id` in the returned credential
      const idUint8Array = Uint8Array.from(Buffer.from(body.id, 'base64'));

      const authenticator = user.authenticators.find(
        (a) => Buffer.compare(a.credentialID, idUint8Array) === 0
      );

      if (!authenticator) {
        throw new Error(
          `Could not find authenticator ${body.id} for user ${user.id}`
        );
      }

      let verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator,
      });

      res.send(verification);
    } catch (error) {
      res.send({ errorMessage: error.message });
    }
  }
);

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
  console.log(`users that are logged in: ${userTable.map((user) => user.id)}`);
});
