import { Command } from "commander";
import { version } from "../macros";
import prettyMs from "pretty-ms";

// @ts-ignore just treat this as any for now as im too lazy to write declarations
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'
import type { SystemError } from "bun";

import https from 'https';
import http from 'http';
import { TLSSocket } from 'tls';
import crypto from "crypto";

import fs from 'fs/promises'
import os from 'os'
import path from "path";
import envPaths from "env-paths";
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
    .option('-p, --passive [port]',             "Perform action passively (be the server). Port defaults to 52110", '52110')

    .option('-w, --passcode <passcode>',        "Specify authentication passcode")
    .option('--no-passcode',                    "Don't use authentication passcode as server")

    .option('--no-validate-fp',                 "Don't prompt to validate connection fingerprint.")
    .option('-t, --trust [yes/no/ask]',         "Auto-trust/untrust identity when unknown")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .action((options) => {
        CA_XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        CA_XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
        CA_oneOf('trust', ['yes','no','ask'])(options);
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

                return { host, port, validateFP: !!flags.validateFp };
            })()
        }

        else return {
            mode: 'server',
            port: flags.passive,
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

        if (flags.passcode === true) return Math.floor(100000 + Math.random() * 900000);

        else return flags.passcode
    })(),

    trust: flags.trust
}

if (settings.mode === 'client') {
    const req = await client({
        hostname: settings.host,
        port: settings.port,
        action: settings.action,
        passcode: settings.passcode,
        validateFP: settings.validateFP,
        contentLength: undefined,
        trust: settings.trust
    });

    if (settings.action === 'send') 
        settings.readstream.pipe(req);

    else
        req.on('response', (res) => {

            const length = (() => {
                const str = res.headers['content-length'];
                const num = Number(str);

                if (Number.isNaN(num)) return undefined;
                else return num;
            })()

            const spinner = spinProgress("Receiving Data", length);

            res.pipe(settings.writestream);

            res.on('data', c => spinner.progress(c.length));

            res.on('error', async e => {
                await spinner.fail();

                if (isSystemError(e)) syscrash(e);
                else throw e;
            })

            res.on('end', () => spinner.finish())
        });
} else {

}

async function client({ hostname, port, action, validateFP, contentLength, passcode, trust }: {
    hostname: string;
    port: number;
    action: 'send' | 'receive';
    validateFP: boolean;
    passcode: string | undefined;
    contentLength: number | undefined;
    trust: 'yes' | 'no' | 'ask';
}): Promise<http.ClientRequest> { return new Promise(async (resolve) => {

    const identity = await getKeyPair();

    const spinner = terminal.spin(`%spin%  Connecting to ${hostname}`)

    const req = https.request({
        hostname, port,
        path: '/v1/antenna',
        method: 'POST',
        headers: {
            'antenna-version': version(),
            'antenna-action': action,
            'antenna-hostname': os.hostname(),
            'authentication': passcode,
            'content-length': contentLength,
            'expect': '100-continue',
        },
        ...identity,
        rejectUnauthorized: false
    })

    req.on('socket', socket => socket.on('secureConnect', async () => {
        req.flushHeaders();

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

        const serverIdHash = crypto.createHash('sha256').update(serverIdentity, 'utf8').digest('hex');

        const existingName = await getIdentityInfo(serverIdHash);

        if (existingName) {
            if (existingName !== serverInfo.hostname) {
                terminal.println(`'${serverInfo.hostname}' was previously known as '${existingName}' (${serverIdHash})`);
                setIdentityInfo(serverIdHash, serverInfo.hostname);
            }

            terminal.println(`'${serverInfo.hostname}' has a trusted identity (${serverIdHash})`);
            req.off('error', onErr);
            return resolve(req)
        }

        const fingerprint = crypto.createHash('sha256')
                                  .update(`${serverIdentity}${identity.cert}`, 'utf8')
                                  .digest('hex')
                                  .slice(0, 8);

        
        terminal.println(`'${serverInfo.hostname}' has an unknown identity (${serverIdHash})`)
        terminal.println("Enter the fingerprint code as shown on the server to verify connection integrety")

        let attempts = 0;
        let input = "";

        do {
            attempts++;

            input = (await terminal.ask("code: ")).trim().replaceAll(/-| /, '').toLowerCase();

            if (input !== fingerprint) {
                terminal.println("Code does not match, try again.")

                if (attempts > 3)
                    terminal.println("\x1b[31mIf you did enter the correct code, this connection may have been hijacked.\x1b[0m")
            }

        } while (input !== fingerprint)

        if (trust === 'ask') {
            if ((await terminal.ask('Trust this identity? [y/n] ')).includes('y'))
                trust = 'yes';

            else
                trust = 'no';
        }

        if (trust === 'yes') {
            setIdentityInfo(serverIdHash, serverInfo.hostname);
            terminal.println(`Identity marked as trusted`);
        } else {
            terminal.println(`Not trusting this identity`);
        }

        req.off('error', onErr);
        resolve(req);
    }))
    
    async function onErr(e: unknown) {
        await spinner.reject();

        if (isSystemError(e)) syscrash(e as SystemError);
        throw e;
    }

    req.on('error', onErr);

}) }

async function getKeyPair(): Promise<{ key: string, cert: string }> {
    const configDir = envPaths('antenna-ft').config;
    const keyPath = path.join(configDir, 'identity.key');
    const certPath = path.join(configDir, 'identity.cert');

    await fs.mkdir(configDir, { recursive: true });

    const key = await (async () => {
        try {
            return fs.readFile(keyPath, 'utf8');
        } catch (err) {

            if ((err as SystemError)?.code === 'ENOENT') {
                const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
                    namedCurve: 'P-256', 
                    publicKeyEncoding: {
                        type: 'spki',
                        format: 'pem'
                    },
                    privateKeyEncoding: {
                        type: 'pkcs8',
                        format: 'pem'
                    }
                });

                await Promise.all([
                    fs.writeFile(keyPath, privateKey, 'utf8'),
                    fs.writeFile(certPath, publicKey, 'utf8')
                ]);

                await fs.chmod(keyPath, 0o600);

                return privateKey;

            } 

            if (isSystemError(err)) syscrash(err as SystemError);

            else throw err;
        }
    })();

    const cert = await (async () => {
        try {
            return fs.readFile(certPath, 'utf8');
        } catch (err) {
            if ((err as SystemError)?.code === 'ENOENT') {
                const publicKey = crypto.createPublicKey({ key, format: 'pem' })
                    .export({
                        type: 'spki',
                        format: 'pem'
                    }) as string;

                await fs.writeFile(certPath, publicKey, 'utf8');

                return publicKey;

            } else throw err;
        }
    })();

    return { key, cert };
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
    console.error(`failure: ${errmsg}`);
    
    process.exit(exitcode)
}

function syscrash(e: SystemError): never {
    const error = errno.errno[e.errno];

    if (!error) throw e;

    crash(`${error.description} (${error.code})${e.path && `: ${e.path}`}`);
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

function spinProgress(actionText: string, length: number|undefined) {
    const spinner = terminal.spin(`%spin%  ${actionText}: -- MiB`);

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

        let newSpinMsg = `%spin%  ${actionText}: ${receivedMiB}`

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
            port: number;
            validateFP: boolean;
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
