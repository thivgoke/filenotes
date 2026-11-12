# Fieldnotes local quiz

## Run locally

1. Install Node.js 18 or newer if it is not already installed.
2. From this folder, run `npm start`.
3. Open `http://127.0.0.1:4173` in your browser and leave the terminal running.

The local server automatically loads every JSON question bank in `question-banks`.
After a session is submitted, it saves the attempt to `session-data/<question-bank-name>-sessions.json`.
For example, attempts for `french-culinary-hospitality.json` are saved to
`session-data/french-culinary-hospitality-sessions.json`.

Usernames and salted scrypt password hashes are stored in the Git-ignored
`data/user-credentials.json`; passwords are not stored in plain text.
`data/user-credentials.example.json` is a safe empty template. The browser keeps
a local copy of quiz progress so an unsynced session can be retried.

## Deploy the full app on Render

GitHub Pages only hosts static files and cannot run this app's Node.js server.
The checked-in `render.yaml` configures the full app, including a persistent disk
for credentials and session JSON files.

1. Push the repository to GitHub.
2. In Render, choose **New → Blueprint** and connect `thivgoke/filenotes`.
3. Before creating the service, enter `thiv@goke.in` for `INITIAL_USERNAME`
   and the account password for `INITIAL_PASSWORD` when prompted. These are
   private Render environment variables; never put the password in GitHub.
4. Create the Blueprint and wait for the service health check to pass.
5. Open the `*.onrender.com` service URL. Sign in with the initial account.

The initial account is created only when the persistent credential file is
empty. The disk keeps account and quiz JSON data across deploys. The app uses a
signed, HTTP-only session cookie and requires sign-in before accepting quiz
attempts. Render's Starter web service and persistent disk may incur charges;
check current pricing before creating the service. Do not enable GitHub Pages
for this full-server app.
