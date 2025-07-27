const net = require('net');
const readline = require('readline');
const cryptoUtils = require('./cryptoUtils');

const client = new net.Socket();
const ecdh = cryptoUtils.generateKeyPair();

let buffer = '';
let aesKey = null;
let stage = 'auth'; // auth → key → chat
let pendingPrompt = null;

let username = '';

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

client.connect(12345, '127.0.0.1', () => {
    console.log('Connected to server.');
});

client.on('close', () => {
    console.log('Disconnected from server');
    process.exit();
});

client.on('data', (data) => {
    buffer += data.toString();

    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);

        if (!aesKey) {
            console.log(line); // Show all server messages during auth phase

            if (line.toLowerCase().includes('type 1') && line.toLowerCase().includes('2 to login')) {
                rl.question('', (choice) => client.write(choice.trim() + '\n'));
            } 
            else if (line.includes('Enter your username') || line.includes('Choose a username')) {
                rl.question('', (name) => {
                    username = name.trim();
                    client.write(username + '\n');
                });
            } 
            else if (line.includes('Enter your password') || line.includes('Choose a password')) {
                rl.question('', (pwd) => client.write(pwd.trim() + '\n'));
            }
            else if (line.includes('Starting secure key exchange')) {
                pendingPrompt = 'server-key';
            }
            else if (pendingPrompt === 'server-key' && /^[A-Za-z0-9+/=]+$/.test(line)) {
                const serverPubKey = cryptoUtils.decodePublicKey(line);
                const sharedSecret = ecdh.computeSecret(serverPubKey);
                aesKey = cryptoUtils.deriveAESKey(sharedSecret);
                client.write(ecdh.getPublicKey('base64') + '\n');
                stage = 'key';
                pendingPrompt = null;
            }
        }
        else if (stage === 'key' && aesKey) {
            try {
                const decrypted = cryptoUtils.decryptAES(line, aesKey);
                if (decrypted.includes('Secure channel established')) {
                    console.log('\n✅ Secure channel established. You can now chat.\n');
                    stage = 'chat';
                    
                    // Now we show the > prompt for chat messages
                    const prompt = () => {
                        rl.question('> ', (input) => {
                            if (input.toLowerCase() === 'exit') {
                                client.end();
                            } else {
                                const encrypted = cryptoUtils.encryptAES(input, aesKey);
                                client.write(encrypted + '\n');
                                prompt(); // Show prompt again after sending
                            }
                        });
                    };
                    prompt();
                }
            } catch (err) {
                console.error('[Decryption error]', err.message);
            }
        }
        else if (stage === 'chat' && aesKey) {
            try {
                const decrypted = cryptoUtils.decryptAES(line, aesKey);
                console.log(decrypted);
            } catch (err) {
                console.error('[Decryption error]', err.message);
            }
        }
    }
}); 

//server
const net = require('net');
const cryptoUtils = require('./cryptoUtils');
const bcrypt = require('bcrypt');
const fs = require('fs');

const USERS_FILE = './users.json';
let users = fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE)) : {};

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

const clients = [];

const server = net.createServer((socket) => {
    console.log('Client connected');
    const ecdh = cryptoUtils.generateKeyPair();
    let buffer = '';
    let stage = 'auth'; // stages: auth → key → chat

    const clientData = {
        socket,
        aesKey: null,
        username: null
    };
    clients.push(clientData);

    socket.write("Welcome to chatty, type 1 to register and 2 to login\n> ");

    socket.on('data', (data) => {
        buffer += data.toString();

        let index;
        while ((index = buffer.indexOf('\n')) !== -1) {
            const line = buffer.slice(0, index).trim();
            buffer = buffer.slice(index + 1);

            if (stage === 'auth') {
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
                const hashed = bcrypt.hashSync(line, 10);
                users[clientData.pendingUsername] = hashed;
                saveUsers();
                clientData.username = clientData.pendingUsername;
                delete clientData.pendingUsername;

                socket.write('Registration successful. Starting secure key exchange...\n');
                socket.write(ecdh.getPublicKey('base64') + '\n');
                stage = 'key';
            }

            else if (stage === 'login-username') {
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
                const clientPubKey = Buffer.from(line, 'base64');
                const sharedSecret = ecdh.computeSecret(clientPubKey);
                clientData.aesKey = cryptoUtils.deriveAESKey(sharedSecret);
                socket.write(cryptoUtils.encryptAES('Secure channel established.', clientData.aesKey) + '\n');
                console.log(`[${clientData.username}] Secure channel established.`);
                stage = 'chat';
            }

            else if (stage === 'chat') {
                try {
                    console.log(`[${clientData.username}]: ${line}`);

                    // Broadcast to others
                    for (const other of clients) {
                        if (other !== clientData && other.aesKey) {
                            const decrypted = cryptoUtils.decryptAES(line, clientData.aesKey);
                            const encrypted = cryptoUtils.encryptAES(`[${clientData.username}]: ${decrypted}`, other.aesKey);
                            other.socket.write(encrypted + '\n');
                        }
                    }
                } catch (err) {
                    console.error('[Decryption failed]', err.message);
                }
            }
        }
    });

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