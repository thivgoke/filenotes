# Fieldnotes local quiz

## Run the app

1. Install Node.js 18 or newer if it is not already installed.
2. From this folder, run `npm start`.
3. Open `http://127.0.0.1:4173` in your browser and leave the terminal running.

The local server automatically loads every JSON question bank in `question-banks`.
After a session is submitted, it saves the attempt to `session-data/<question-bank-name>-sessions.json`.
For example, attempts for `french-culinary-hospitality.json` are saved to
`session-data/french-culinary-hospitality-sessions.json`.

Usernames and salted scrypt password hashes are stored in `data/user-credentials.json`;
passwords are not stored in plain text. The browser also keeps a local copy of
quiz progress so an unsynced session can be retried the next time the app opens.
The server listens only on this computer and does not provide remote access.

# filenotes
