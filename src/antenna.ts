import { Command } from "commander";
import prettyMs from "pretty-ms";

// @ts-ignore just treat this as any for now as im too lazy to write declarations
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'

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
    
parser
    .option('-S, --send',                       "Send file")
    .option('-R, --receive',                    "Receive file")

    .option('-a, --active <host>',              "Perform action actively (be the client)")
    .option('-p, --passive [port]',             "Perform action passively (be the server). Port defaults to 52110")

    .option('-w, --passcode <passcode>',        "Specify authentication passcode")
    .option('-n, --no-passcode',                "Don't use authentication passcode as server")

    .option('--no-validate-fp',                 "Don't validate connection fingerprint.")
    .option('-t, --trust [yes/no/ask]',         "Auto-trust/untrust identity when unknown")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .action((options) => {
        CA_XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        CA_XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
        CA_oneOf('trust', ['yes','no','ask',undefined])(options);
        CA_type('passive', ['boolean', 'number', 'undefined'])(options);
    })
    
parser.parse();

const flags = parser.opts();

const settings: AppSettings = {
    // Modes
    ...(() => {
        if (flags.active) return {
            mode: 'client',
            host: flags.active
        }

        else return {
            mode: 'server',
            port: typeof flags.passive === 'number' ? flags.passive : 52110
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
}

if (settings.mode === 'client') {
    const req = await client({
        ...settings,
        url: new URL(`antenna://${settings.host}`),
        contentLength: (settings as { length: number|undefined }).length,
    });
    terminal.println('');

    if (settings.action === 'send') {
        settings.readstream.pipe(req);
        await attachProgressSpinner('Transmitting Data', settings.length, settings.readstream)

    } else {
        await new Promise<void>(resolve => {
            req.on('response', async (res) => {
                res.pipe(settings.writestream);
                await attachProgressSpinner('Receiving Data', toNumOrUndefined(res.headers['content-length']), res)
                resolve();
            });
        })
    }
} else {
    const { req, res } = await server({
        ...settings,
        contentLength: (settings as { length: number|undefined }).length
    })
    terminal.println('');

    if (settings.action === 'send') {
        settings.readstream.pipe(res);
        await attachProgressSpinner('Transmitting Data', settings.length, settings.readstream)
    } else {
        req.pipe(settings.writestream);
        await attachProgressSpinner('Receiving Data', toNumOrUndefined(req.headers['content-length']), req)
    }
}

terminal.println("All done!");

async function server({ port, action, passcode, contentLength, trust, validateFP }: {
    port: number;
    action: 'send' | 'receive';
    passcode: string | undefined;
    contentLength: number | undefined;
    trust: 'yes' | 'no' | 'ask';
    validateFP: boolean;
}) { return new Promise<{req:http.IncomingMessage, res:http.ServerResponse}>(async (resolve) => {
    const identity = await getKeyPair();

    if (passcode) terminal.println(`Passcode: ${passcode}`);
    else terminal.println(`No passcode required`)

    const spinner = terminal.spin(`%spin% Awaiting connection on port ${port}`)

    const server = https.createServer({
        ...identity,
        requestCert: true,
        rejectUnauthorized: false
    }, async (req, res) => {
        try {
            const cert = (req.socket as TLSSocket).getPeerCertificate();

            if (passcode && req.headers['authorization'] !== `${passcode}`)
                return res.writeHead(403).end('Passcode Incorrect');

            if (!cert || Object.keys(cert).length === 0) 
                return res.writeHead(496).end('Client Identity Required');
            
            if (req.url !== '/v1/antenna') 
                return res.writeHead(404).end('Not Found');

            if (req.method !== 'POST') 
                return res.writeHead(405).end('Method Not Allowed')

            if (req.headers['antenna-action'] !== (action==='send' ? 'receive' : 'send'))
                return res.writeHead(405).end('Incompatible Action')

            server.close();

            req.on('error', e => { throw e })

            res.writeHead(200, {
                'antenna-action': action,
                'antenna-hostname': os.hostname(),
                'antenna-content-length': contentLength ?? ''
            })

            res.flushHeaders();

            await spinner.resolve();

            const peerName = (() => {
                const name = req.headers['antenna-hostname'];
                return typeof name === 'string' ? name : 'No Name';
            })();
        
            const selfId = pemToRaw(identity.cert);
            const peerId = cert.raw;
            const peerHash = sha256(cert.raw);

            const fp = getFingerprint(selfId, peerId).toUpperCase();

            terminal.println(`'${peerName}' has connected via ${req.socket.remoteAddress}!`)

            if (validateFP) await verifyConnection({ peerName, peerHash, fp, trust });

            resolve({req, res})
        } catch (e) {
            throw e;
        }
    })

    // error handling
    server.on('error', e => { throw e });
    server.on('clientError', e => { throw e });
    server.on('tlsClientError', e => { throw e });

    server.listen(port);
})}

async function client(params: {
    url: URL;
    action: 'send' | 'receive';
    validateFP: boolean;
    passcode: string | undefined;
    contentLength: number | undefined;
    trust: 'yes' | 'no' | 'ask';
}): Promise<http.ClientRequest> { return new Promise(async (resolve) => {

    const { url, action, validateFP, contentLength, passcode, trust } = params;

    const identity = await getKeyPair();

    const spinner = terminal.spin(`%spin% Connecting to ${url.host}`)

    if (url.port === '')
        url.port = "52110";

    url.pathname = '/v1/antenna'

    const req = https.request(url, {
        path: '/v1/antenna',
        protocol: 'https:',
        method: 'POST',
        headers: {
            'host': url.host,
   //         'antenna-version': version(),
            'antenna-action': action,
            'antenna-hostname': os.hostname(),
            'authorization': passcode ?? '',
            'antenna-content-length': contentLength ?? '',
        },
        ...identity,
        setDefaultHeaders: false,
        rejectUnauthorized: false,
    })

    req.on('response', async res => {
        try {
            if (res.statusCode !== 200) {
                await spinner.reject();
                crash(`server replied: ${res.statusCode} ${await (async () => {
                    const chunks = [];
                    for await (const chunk of res) chunks.push(chunk);
                    return Buffer.concat(chunks).toString();
                })()}`);
            }

            await spinner.resolve();

            const peerName = (() => {
                const name = res.headers['antenna-hostname'];
                return typeof name === 'string' ? name : 'No Name';
            })();

            const peerCert = (req.socket as TLSSocket).getPeerCertificate(true);
            const peerId = peerCert.raw;
            const peerHash = sha256(peerId)
            const selfId = pemToRaw(identity.cert)

            if (!validateFP) {
                req.off('error', onErr);
                return resolve(req);
            }

            const trusted = await checkIdentity(peerHash, peerName);

            if (!trusted) await checkFingerprint(getFingerprint(peerId, selfId));

            await handleTrusting(peerHash, peerName, trust);

            req.off('error', onErr);
            req.end();

            resolve(req);

        } catch (e) { 
            throw e;
        }
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
                "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1", 
                "-pkeyopt", "ec_param_enc:named_curve",     
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

function pemToRaw(pem: string): Buffer {
    const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/, '')
                   .replace(/-----END CERTIFICATE-----/, '')
                   .replace(/\s+/g, '');

    return Buffer.from(b64, 'base64');
}

function getFingerprint(peer1: Buffer, peer2: Buffer) {
    return sha256(Buffer.concat([peer1, peer2])).slice(0, 8);
}

function sha256(data: Buffer) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

async function verifyConnection({ peerHash, peerName, fp, trust }: { peerHash: string, peerName: string, fp: string, trust: 'yes'|'no'|'ask' }) {
    const existingName = await getIdentityInfo(peerHash);

    if ((() => {
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
    })()) {
        terminal.println(`Connection Fingerprint: ${fp.slice(0,4)}-${fp.slice(4)}`)
        terminal.println('Is the code shown above identical on the other side?')
        
        if (!(await terminal.ask('[y/n] ')).toLowerCase().includes('y'))
            crash("can't verify connection integrity, aborting")

    } else trust = 'yes';


    if (trust === 'ask') {
        if ((await terminal.ask('Trust this identity from now on? [y/n] ')).includes('y'))
            trust = 'yes';

        else
            trust = 'no';
    }

    if (trust === 'yes') {
        setIdentityInfo(peerHash, peerName);
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

async function attachProgressSpinner(actionText: string, length: number|undefined, rs: NodeJS.ReadableStream) {
    const spinner = spinProgress(actionText, length);

    rs.on('data', (c: Buffer) => spinner.progress(c.length))
    rs.on('error', async (e: unknown) => {
        await spinner.fail();

        if (isSystemError(e)) syscrash(e as SystemError);
            else throw e;
    })
    rs.on('close', () => spinner.finish());

    return spinner.promise;
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
        },

        promise: spinner.promise
    }
}

type AppSettings = (
        { 
            mode: 'client';
            host: string;
        } | {
            mode: 'server';
            port: number;
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
    validateFP: boolean;
}

type SystemError = Error & {
    code: string;
    errno: number;
    path?: string;
}

type TypeofResult =
    | "undefined"
    | "object"
    | "boolean"
    | "number"
    | "bigint"
    | "string"
    | "symbol"
    | "function";


// (C)ommander (A)ctions
function CA_XOR(flag1: string, flag2: string, errmsg: string) {
    return function(options: Record<string, unknown>) {
        if (!!options[flag1] !== !!options[flag2]) return;

        else crash(errmsg);
    }
}

function CA_type(flag: string, type: TypeofResult[]) {
    return function(option: Record<string, unknown>) {
        if (!type.includes(typeof option[flag] as TypeofResult))
            crash(`'--${flag}' must be one of following type: ${type.join(', ')}. Got '${option[flag]}' instead.`)
    }
}

function CA_oneOf(flag: string, possibilities: any[]) {
    return function(options: Record<string, unknown>) {
        if (!possibilities.includes(options[flag]))
            crash(`'--${flag}' must be one of: ${possibilities.join(', ')}`);
    }
}
