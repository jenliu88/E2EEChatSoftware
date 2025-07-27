const net = require('net');
const readline = require('readline');
const cryptoUtils = require('./cryptoUtils');

const client = new net.Socket();
const ecdh = cryptoUtils.ECDHkeyPair();

let buffer = '';
let stage = 'auth'; // auth -> key -> chat
let pendingPrompt = null;
let aesKey = null;
let username = '';

// store public keys and AES keys of peers
const peerPubKeys = {};
const peerAESKeys = {};

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

        let parsed;
        try {
            parsed = JSON.parse(line);
        } catch {
            //prompt or messages
            parsed = line;
        }

        // login process
        if (!aesKey && typeof parsed === 'string') {
            console.log(parsed);

            if (parsed.toLowerCase().includes('type 1') && parsed.toLowerCase().includes('2 to login')) {
                rl.question('', (choice) => client.write(choice.trim() + '\n'));
            } 
            else if (parsed.includes('Enter your username') || parsed.includes('Choose a username')) {
                rl.question('', (name) => {
                    username = name.trim();
                    client.write(username + '\n');
                });
            } 
            else if (parsed.includes('Enter your password') || parsed.includes('Choose a password')) {
                rl.question('', (pwd) => client.write(pwd.trim() + '\n'));
            }
            else if (parsed.includes('Starting secure key exchange') ||
                    parsed.includes('Exchanging public keys')
            ) {
                pendingPrompt = 'server-key';
            }
            // db checking it's a base64-encoded server public key
            else if (pendingPrompt === 'server-key' && /^[A-Za-z0-9+/=]+$/.test(parsed)) {
                const serverPubKey = cryptoUtils.decodePublicKey(parsed);
                const sharedSecret = ecdh.computeSecret(serverPubKey);
                aesKey = cryptoUtils.AESKey(sharedSecret);
                //send public key to the server
                client.write(ecdh.getPublicKey('base64') + '\n');
                stage = 'key';
                pendingPrompt = null;
            }
        }

        // message encryption and decryption
        else if (stage === 'key' && aesKey && typeof parsed === 'string') {
            try {
                const decrypted = cryptoUtils.decryptMessage(parsed, aesKey);
                if (decrypted.includes('Secure channel established')) {
                    console.log('\n Secure channel has been established, have fun chatting :)\n End the chat by typing "exit"\n');
                    stage = 'chat';

                    //chat input loop
                    const prompt = () => {
                        rl.question('> ', (input) => {
                            if (input.toLowerCase() === 'exit') {
                                client.end();
                            } else {
                                for (const peer in peerAESKeys) {
                                    const encrypted = cryptoUtils.encryptMessage(`[${username}]: ${input}`, peerAESKeys[peer]);
                                    const payload = {
                                        type: 'message',
                                        to: peer,
                                        from: username,
                                        body: encrypted
                                    };
                                    client.write(JSON.stringify(payload) + '\n');
                                }
                                prompt(); // keep asking for input
                            }
                        });
                    };
                    prompt();
                }
            } catch (err) {
                console.error('[Decryption error]', err.message);
            }
        }

        //chatting, exchange peer messages and keys
        else if (stage === 'chat') {
            //exchanging peer public keys
            if (parsed.type === 'peer-public-key') {
                peerPubKeys[parsed.username] = parsed.key;
                const peerECDHKey = cryptoUtils.decodePublicKey(parsed.key);
                const sharedSecret = ecdh.computeSecret(peerECDHKey);
                peerAESKeys[parsed.username] = cryptoUtils.AESKey(sharedSecret);
            }
            else if (parsed.type === 'message') {
                // decrypt and display messages from peers
                const key = peerAESKeys[parsed.from];
                if (key) {
                    try {
                        const msg = cryptoUtils.decryptMessage(parsed.body, key);
                        console.log(msg);
                    } catch (err) {
                        console.error('[Message decrypt error]', err.message);
                    }
                }
            }
        }
    }
});
