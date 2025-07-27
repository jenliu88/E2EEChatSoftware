const net = require('net');
const cryptoUtils = require('./cryptoUtils');
const bcrypt = require('bcrypt');
const fs = require('fs');

const USERS_FILE = './users.json';

// load existing users from file
let users;
if (fs.existsSync(USERS_FILE)) {
    const file = fs.readFileSync(USERS_FILE);
    users = JSON.parse(file);
} else {
    users = {};
}

// save current users
function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
//store connected clients
const clients = [];

const server = net.createServer((socket) => {
    console.log('Client connected');

    const ecdh = cryptoUtils.ECDHkeyPair();
    let buffer = '';
    let stage = 'auth'; //intial auth

    const clientData = {
        socket,
        aesKey: null,
        username: null,
        pubKey: null
    };
    clients.push(clientData);

    //prompt client
    socket.write("Welcome to chatty, type 1 to register and 2 to login\n> ");

    socket.on('data', (data) => {
        buffer += data.toString();

        let index;
        while ((index = buffer.indexOf('\n')) !== -1) {
            const line = buffer.slice(0, index).trim();
            buffer = buffer.slice(index + 1);

            if (stage === 'auth') {
                // login/register
                if (line === '2') {
                    socket.write('Enter your username:\n> ');
                    stage = 'login-username';
                } else if (line === '1') {
                    socket.write('Choose a username:\n> ');
                    stage = 'register-username';
                } else {
                    socket.write('Invalid option. Type:\n1. Login\n2. Register\n> ');
                }
            }

            else if (stage === 'register-username') {
                // register a new user
                if (users[line]) {
                    socket.write('Username already exists. Try again:\n1. Login\n2. Register\n> ');
                    stage = 'auth';
                } else {
                    clientData.pendingUsername = line;
                    socket.write('Choose a password:\n> ');
                    stage = 'register-password';
                }
            }

            else if (stage === 'register-password') {
                //hash pw
                const hashed = bcrypt.hashSync(line, 10);
                users[clientData.pendingUsername] = hashed;
                saveUsers();

                clientData.username = clientData.pendingUsername;
                delete clientData.pendingUsername;

                socket.write('Registration successful. Exchanging public keys...\n');
                socket.write(ecdh.getPublicKey('base64') + '\n');
                stage = 'key';
            }

            else if (stage === 'login-username') {
                //loggin in - check if user exists
                if (!users[line]) {
                    socket.write('Username not found. Try again:\n1. Login\n2. Register\n> ');
                    stage = 'auth';
                } else {
                    clientData.pendingUsername = line;
                    socket.write('Enter your password:\n> ');
                    stage = 'login-password';
                }
            }

            else if (stage === 'login-password') {
                // compare with stored hash
                const hash = users[clientData.pendingUsername];
                if (!bcrypt.compareSync(line, hash)) {
                    socket.write('Incorrect password. Try again:\n1. Login\n2. Register\n> ');
                    stage = 'auth';
                } else {
                    clientData.username = clientData.pendingUsername;
                    delete clientData.pendingUsername;

                    socket.write('Login successful. Starting secure key exchange...\n');
                    socket.write(ecdh.getPublicKey('base64') + '\n');
                    stage = 'key';
                }
            }

            else if (stage === 'key') {
                //exchange public keys and derive shared AES key
                const clientPubKey = Buffer.from(line, 'base64');
                const sharedSecret = ecdh.computeSecret(clientPubKey);
                clientData.aesKey = cryptoUtils.AESKey(sharedSecret);
                clientData.pubKey = line;

                socket.write(cryptoUtils.encryptMessage('Secure channel established.', clientData.aesKey) + '\n');

                // share this client's public key with all others
                for (const other of clients) {
                    if (other !== clientData && other.username) {
                        // Send this client's key to others
                        other.socket.write(JSON.stringify({
                            type: 'peer-public-key',
                            username: clientData.username,
                            key: clientData.pubKey
                        }) + '\n');

                        // send other clients' keys to this client
                        socket.write(JSON.stringify({
                            type: 'peer-public-key',
                            username: other.username,
                            key: other.pubKey
                        }) + '\n');
                    }
                }

                stage = 'chat';
                console.log(`[${clientData.username}] Secure channel established.`);
            }

            else if (stage === 'chat') {
                let parsed;
                try {
                    parsed = JSON.parse(line);
                } catch {
                    continue;
                }

                if (parsed.type === 'message') {
                    // Forward message to the target user
                    const target = clients.find(c => c.username === parsed.to);
                    if (target) {
                        target.socket.write(JSON.stringify(parsed) + '\n');
                    }
                }
            }
        }
    });

    // handle client disconnection
    socket.on('close', () => {
        console.log(`[${clientData.username || 'unknown'}] disconnected`);
        const index = clients.findIndex(c => c.socket === socket);
        if (index !== -1) clients.splice(index, 1);
    });

    socket.on('error', (err) => {
        console.error('[Socket error]', err.message);
    });
});

const PORT = 12345;
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
