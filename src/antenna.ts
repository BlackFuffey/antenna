import { Command } from "commander";
import { version } from "../macros";
import prettyMs from "pretty-ms";

// @ts-ignore just treat this as any for now as im too lazy to write declarations
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'
import type { SystemError } from "bun";

import https from 'https';
import http  from 'http';
import { TLSSocket } from 'tls';
import crypto from "crypto";

import fs from 'fs/promises'
import os from 'os'
import path from "path";
import envPaths from "env-paths";

import { execFile } from 'child_process';
import { promisify } from "util";

const execFileAsync = promisify(execFile);

import terminal from "./terminal";

const parser = new Command();

parser
    .name('antenna')
    .usage('(--send | --receive) (--active <host> | --passive [port]) [other options]')
    .description('Quickly and securely transfer file over IP directly with no setup')
    .version(version())
    
parser
    .option('-S, --send',                       "Send file")
    .option('-R, --receive',                    "Receive file")

    .option('-a, --active <host>',              "Perform action actively (be the client)")
    .option('-p, --passive [port]',             "Perform action passively (be the server). Port defaults to 52110")

    .option('-w, --passcode <passcode>',        "Specify authentication passcode")
    .option('-n, --no-passcode',                    "Don't use authentication passcode as server")

    .option('--no-validate-fp',                 "Don't validate connection fingerprint.")
    .option('-t, --trust [yes/no/ask]',         "Auto-trust/untrust identity when unknown")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .action((options) => {
        CA_XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        CA_XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
        CA_oneOf('trust', ['yes','no','ask',undefined])(options);
    })
    
parser.parse();

const flags = parser.opts();

const settings: AppSettings = {
    // Modes
    ...(() => {
        if (flags.active) return {
            mode: 'client',
            ...(() => {
                const endpoint = flags.active;
                const match = endpoint.match( /^(.+?)(?::([0-9]{1,5}))?$/ );

                if (!match) throw new Error(`Failed to parse endpoint "${endpoint}"`);

                const host = match[1]!;
                const port = match[2] !== undefined ? parseInt(match[2], 10) : 52110;

                if (Number.isNaN(port)) throw new Error(`Unable to parse port. Match: ${match}`);

                return { host };
            })()
        }

        else return {
            mode: 'server',
        }
    })(),

    // Send or receive
    ...(() => {
        try {
            if (flags.send) return {
                action: 'send',
                readstream: flags.file==='-' ? process.stdin : fsSync.createReadStream(flags.file),
                length: flags.file==='-' ? undefined : getFileLengthSync(flags.file)
            }

            else return {
                action: 'receive',
                writestream: flags.file==='-' ? process.stdout : fsSync.createWriteStream(flags.file)
            }
        } catch (e: unknown) {
            if (isSystemError(e)) syscrash(e as SystemError);

            else throw e;
        }
    })(),

    passcode: (() => {
        if (flags.passcode === false) return undefined;

        if (flags.passive && [undefined, true].includes(flags.passcode)) 
            return Math.floor(100000 + Math.random() * 900000);

        else return flags.passcode
    })(),

    trust: flags.trust ?? 'ask',
    validateFP: !flags.noValidateFp,
    port: typeof flags.passive === 'number' ? flags.passive : 52110
}

if (settings.mode === 'client') {
    const req = await client({
        ...settings,
        hostname: settings.host,
        contentLength: (settings as { length: number|undefined }).length,
    });

    if (settings.action === 'send') {
        settings.readstream.pipe(req);
        attachProgressSpinner('Transmitting Data', settings.length, settings.readstream)

    } else {
        req.on('response', (res) => {
            res.pipe(settings.writestream);
            attachProgressSpinner('Receiving Data', toNumOrUndefined(res.headers['content-length']), res)
        });
    }
} else {
    const { req, res } = await server({
        ...settings,
        contentLength: (settings as { length: number|undefined }).length
    })

    if (settings.action === 'send') {
        settings.readstream.pipe(res);
        attachProgressSpinner('Transmitting Data', settings.length, settings.readstream)
    } else {
        req.pipe(settings.writestream);
        attachProgressSpinner('Receiving Data', toNumOrUndefined(req.headers['content-length']), req)
    }
}

async function server({ port, action, passcode, contentLength, trust }: {
    port: number;
    action: 'send' | 'receive';
    passcode: string | undefined;
    contentLength: number | undefined;
    trust: 'yes' | 'no' | 'ask';
}) { return new Promise<{req:http.IncomingMessage, res:http.ServerResponse}>(async (resolve) => {
    const identity = await getKeyPair();

    if (passcode) terminal.println(`Passcode: ${passcode}`);
    else terminal.println(`No passcode required`)

    const spinner = terminal.spin(`%spin% Listening on port ${port}`)

    const server = https.createServer({
        ...identity,
        requestCert: true,
        rejectUnauthorized: false
    }, async (req, res) => {
        console.log('request received')
        const cert = (req.socket as TLSSocket).getPeerCertificate();

        if (passcode && req.headers['authorization'] !== passcode)
            return res.writeHead(403).end('Forbidden\n');

        if (!cert || Object.keys(cert).length === 0) 
            return res.writeHead(496).end('Client Identity Required\n');
        
        if (req.url !== '/v1/antenna') 
            return res.writeHead(404).end('Not Found\n');

        if (req.headers['antenna-action'] === (action==='send' ? 'receive' : 'send'))
            return res.writeHead(405).end('Incompatible Action\n')

        server.close();

        res.writeHead(100, {
            'antenna-version': version(),
            'antenna-action': action,
            'antenna-hostname': os.hostname(),
            'content-length': contentLength
        }).write("Continue\n")

        await spinner.resolve();

        const peerId = crypto.createPublicKey(cert.raw)
                             .export({ type: 'spki', format: 'pem' }) as string
        const peerName = (() => {
            const name = req.headers['antenna-hostname'];
            return typeof name === 'string' ? name : 'No Name';
        })();
    
        const fp = getFingerprint(identity.cert, peerId).toUpperCase();

        terminal.println(`Connection Fingerprint: ${fp.slice(0,4)}-${fp.slice(4)}`);

        if (!await checkIdentity(peerId, peerName))
                handleTrusting(peerId, peerName, trust);

        return resolve({req, res})
    })

    server.on('tlsClientError', (err, socket) => {
        console.error('TLS client error:', err.message);
    });

    server.listen(port);
})}

async function client(params: {
    hostname: string;
    port: number;
    action: 'send' | 'receive';
    validateFP: boolean;
    passcode: string | undefined;
    contentLength: number | undefined;
    trust: 'yes' | 'no' | 'ask';
}): Promise<http.ClientRequest> { return new Promise(async (resolve) => {

    const { hostname, port, action, validateFP, contentLength, passcode, trust } = params;

    const identity = await getKeyPair();

    const spinner = terminal.spin(`%spin% Connecting to ${hostname} on port ${port}`)

    const req = https.request({
        hostname, port,
        path: '/v1/antenna',
        method: 'POST',
        headers: {
            'antenna-version': version(),
            'antenna-action': action,
            'antenna-hostname': os.hostname(),
            'authorization': passcode ?? '',
            'content-length': contentLength ?? '',
            'expect': '100-continue',
        },
        ...identity,
        rejectUnauthorized: false,
    })


    req.on('socket', socket => {
        socket.on('connectSecure', async () => {
            const serverInfo: { 
                version: string | null, 
                hostname: string
            } = await (() => new Promise((resolve) => req.on('response', async res => {
                    if (res.statusCode !== 100) {
                        await spinner.reject();
                        crash(`server replied '${res.statusCode} ${res.statusMessage}`);
                    }

                    await spinner.resolve();

                    const version = res.headers['antenna-version'];
                    const hostname = res.headers['antenna-hostname'];

                    return resolve({
                        version: typeof version === 'string' ? version : null,
                        hostname: typeof hostname === 'string' ? hostname : 'No Name'
                    })
                })))()

            if (!validateFP) {
                req.off('error', onErr);
                return resolve(req);
            }

            const serverIdentity = crypto.createPublicKey(
                (socket as TLSSocket).getPeerCertificate(true).raw
            ).export({ type: 'spki', format: 'pem' }) as string

            const trusted = await checkIdentity(serverIdentity, serverInfo.hostname);

            if (!trusted) checkFingerprint(getFingerprint(identity.cert, serverIdentity));

            handleTrusting(identity.cert, serverIdentity, trust);

            req.off('error', onErr);
            resolve(req);
        })

        socket.on('error', onErr)
    })
    
    async function onErr(e: unknown) {
        await spinner.reject();

        if ((e as any).code === 'ERR_INVALID_URL') crash('invalid host')

        if (isSystemError(e)) syscrash(e as SystemError);
        throw e;
    }

    req.on('error', onErr);

    req.flushHeaders();
}) }

async function getKeyPair(): Promise<{ key: string, cert: string }> {
    const configDir = envPaths('antenna-ft').config;
    const keyPath = path.join(configDir, 'identity.key');
    const certPath = path.join(configDir, 'identity.cert');

    await fs.mkdir(configDir, { recursive: true });

    try {
        const [ key, cert ] = await Promise.all([
            fs.readFile(keyPath, 'utf8'),
            fs.readFile(certPath, 'utf8')
        ]);

        return { key, cert }
    } catch (err) {
        if ((err as SystemError)?.code === 'ENOENT') {
            await execFileAsync("openssl", [
                "req",
                "-x509",
                "-newkey", "ed25519",
                "-nodes",
                "-keyout", keyPath,
                "-out", certPath,
                "-days", "365000",
                "-subj", "/CN=localhost"
            ]);

            await fs.chmod(keyPath, 0o600);
            return getKeyPair();

        } else throw err;
    }
}

function getFingerprint(selfId: string, peerId: string) {
    return crypto.createHash('sha256')
                 .update(`${peerId}${selfId}`, 'utf8')
                 .digest('hex')
                 .slice(0, 8);
}

async function checkFingerprint(fp: string) {
    terminal.println("Enter the fingerprint code as shown on the server to verify connection integrety")

    let attempts = 0;
    let input = "";

    do {
        attempts++;

        input = (await terminal.ask("code: ")).trim().replaceAll(/-| /, '').toLowerCase();

        if (input !== fp) {
            terminal.println("Code does not match, try again.")

            if (attempts > 3)
                terminal.println("\x1b[31mIf you did enter the correct code, this connection may have been hijacked.\x1b[0m")
        }

    } while (input !== fp)
}

async function checkIdentity(peerId: string, peerName: string) {
    const peerHash = crypto.createHash('sha256').update(peerId, 'utf8').digest('hex');

    const existingName = await getIdentityInfo(peerHash);

    if (existingName) {
        if (existingName !== peerName) {
            terminal.println(`'${peerName}' was previously known as '${existingName}' (${peerHash})`);
            setIdentityInfo(peerHash, peerName);
        }

        terminal.println(`'${peerName}' has a trusted identity (${peerHash})`);
        return true;
    }

    terminal.println(`'${peerName}' has an unknown identity (${peerHash})`)
    return false;
}

async function handleTrusting(identity: string, hostname: string, trust: 'yes'|'no'|'ask') {
    if (trust === 'ask') {
        if ((await terminal.ask('Trust this identity? [y/n] ')).includes('y'))
            trust = 'yes';

        else
            trust = 'no';
    }

    if (trust === 'yes') {
        setIdentityInfo(identity, hostname);
        terminal.println(`Identity marked as trusted`);
    } else {
        terminal.println(`Not trusting this identity`);
    }
}

async function getIdentityInfo(identity: string) {
    const configDir = envPaths('antenna-ft').config;
    const trustListPath = path.join(configDir, 'trusted.json');

    try {
        const list = JSON.parse(await fs.readFile(trustListPath, 'utf8'));
        return list[identity] || null;
    } catch (e) {
        if ((e as SystemError)?.code === 'ENOENT')
            return null;

        throw e;
    }
}

async function setIdentityInfo(identity: string, hostname?: string) {
    const configDir = envPaths('antenna-ft').config;
    const trustListPath = path.join(configDir, 'trusted.json');

    await fs.mkdir(configDir, { recursive: true });

    const list = JSON.parse(await fs.readFile(trustListPath, 'utf8'));
    list[identity] = hostname;
    
    return fs.writeFile(trustListPath, JSON.stringify(list));
}

function isSystemError(e: unknown) {
    return (e instanceof Error) && (typeof (e as SystemError).code === 'string');
}

function crash(errmsg: string, exitcode:number|null=1): never {
    console.error(`fatal: ${errmsg}`);
    
    process.exit(exitcode)
}

function syscrash(e: SystemError): never {
    const error = errno.code[e.code];

    if (!error) throw e;

    crash(`${error.description} (${error.code})${e.path ? `: ${e.path}` : ''}`);
}

function warn(errmsg: string): void {
    console.error(`warning: ${errmsg}`);
}

function syswarn(e: SystemError): void {
    const error = errno.errno[e.errno];

    if (!error) throw e;

    warn(`${error.description} (${error.code})${e.path && `: ${e.path}`}`);
}

function getFileLengthSync(filepath: string): number | undefined {
    try {
        return fsSync.statSync(filepath).size;
    } catch (e) {
        if (isSystemError(e)) {
            syswarn(e as SystemError);
            return undefined;
        }

        else throw e;
    }
}

function toNumOrUndefined(str: any) {
    const num = Number(str);

    if (Number.isNaN(num)) return undefined;
        else return num;
}

function attachProgressSpinner(actionText: string, length: number|undefined, rs: NodeJS.ReadableStream) {
    const spinner = spinProgress(actionText, length);

    rs.on('data', (c: Buffer) => spinner.progress(c.length))
    rs.on('error', async (e: unknown) => {
        await spinner.fail();

        if (isSystemError(e)) syscrash(e as SystemError);
            else throw e;
    })
    rs.on('close', () => spinner.finish());
}

function spinProgress(actionText: string, length: number|undefined) {
    const spinner = terminal.spin(`%spin% ${actionText}: -- MiB`);

    let lastReceived = 0;
    let totalReceived = 0;
    const history: number[] = [];
    const maxHistory = 5
    let lastUpdated = Date.now();

    const interval = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - lastUpdated) / 1000; // seconds

        const bytesPerSec = elapsed > 0 ? lastReceived / elapsed : 0;

        const receivedMiB = (totalReceived / (1024 * 1024)).toFixed(2);
        const speedMiB = (bytesPerSec / (1024 * 1024)).toFixed(2);

        history.push(bytesPerSec);
        if (history.length > maxHistory) history.shift();

        const avgBytesPerSec = history.length > 0 
            ? history.reduce((a, b) => a + b, 0) / history.length 
            : 0;

        let newSpinMsg = `%spin% ${actionText}: ${receivedMiB}`

        if (length) {
            const percentage = Math.floor(totalReceived / length * 100);
            const etaSec = Math.round((length - totalReceived)! / avgBytesPerSec); // seconds

            const totalMiB = (length / (1024 * 1024)).toFixed(2);

            newSpinMsg += `/${totalMiB}MiB ${percentage}% | ${speedMiB} MiB/s | ETA ${etaSec===Infinity ? '--' : prettyMs(etaSec * 1000)}`

        } else newSpinMsg += `MiB | ${speedMiB} MiB/s | Content Length Unknown`

        lastReceived = 0;
        lastUpdated = now;

        spinner.setline(newSpinMsg)
    }, 1000)
    
    return {
        progress(amount: number) {
            lastReceived += amount;
            totalReceived += amount;
        },

        async finish() {
            clearInterval(interval);
            return spinner.resolve();
        },

        async fail() {
            clearInterval(interval);
            return spinner.reject();
        }
    }
}

type AppSettings = (
        { 
            mode: 'client';
            host: string;
        } | {
            mode: 'server';
        }
) & (
        {
            action: 'send';
            readstream: ReadStream | NodeJS.ReadStream;
            length: number | undefined;
        } | {
            action: 'receive';
            writestream: WriteStream | NodeJS.WriteStream
        }
) & {
    passcode: string | undefined;
    trust: 'yes' | 'no' | 'ask';
    port: number;
    validateFP: boolean;
}

// (C)ommander (A)ctions
function CA_XOR(flag1: string, flag2: string, errmsg: string) {
    return function(options: Record<string, unknown>) {
        if (!!options[flag1] !== !!options[flag2]) return;

        else crash(errmsg);
    }
}

function CA_runIf(flag: string, callback: ()=>any) {
    return function(option: Record<string, unknown>) {
        if (option[flag]) callback()
    }
}

function CA_oneOf(flag: string, possibilities: any[]) {
    return function(options: Record<string, unknown>) {
        if (!possibilities.includes(options[flag]))
            crash(`'--${flag}' must be one of: ${possibilities.join(', ')}`);
    }
}
