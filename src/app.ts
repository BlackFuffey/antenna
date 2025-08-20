import { Command } from "commander";
import { version } from "../macros";

// @ts-ignore just treat this as any for now as im too lazy to write declarations
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'
import type { SystemError } from "bun";

import https from 'https';
import http from 'http';
import envPaths from "env-paths";

import fs from 'fs/promises'
import os from 'os'
import path from "path";
import crypto from "crypto";

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

    .option('-w, --passcode <passcode>',        "Passcode for authentication (only effective in active mode)")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .option('--tsl-type {regular|mutual}',                    "Disable fingerprint validation.")

    .option('-v, --version',           "Check version information")

    .action((options) => {
        CA_XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        CA_XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
    })
    
parser.parse();

const flags = parser.opts();

const settings: AppSettings = {
    // Modes
    ...(() => {
        if (flags.active) return {
            mode: 'client',
            passcode: flags.passcode,
            ...(() => {
                const endpoint = flags.active;
                const match = endpoint.match( /^(.+?)(?::([0-9]{1,5}))?$/ );

                if (!match) throw new Error(`Failed to parse endpoint "${endpoint}"`);

                const host = match[1]!;
                const port = match[2] !== undefined ? parseInt(match[2], 10) : 52110;

                if (Number.isNaN(port)) throw new Error(`Unable to parse port. Match: ${match}`);

                return { host, port };
            })()
        }

        else return {
            mode: 'server',
            port: flags.passive,
            useTsl: flags.tsl,
            usePasscode: flags.usePasscode,
            multi: flags.mult
        }
    })(),

    // Send or receive
    ...(() => {
        try {
            if (flags.send) return {
                action: 'send',
                readstream: flags.file==='-' ? process.stdin : fsSync.createReadStream(flags.file)
            }

            else return {
                action: 'receive',
                writestream: flags.file==='-' ? process.stdout : fsSync.createWriteStream(flags.file)
            }
        } catch (e: unknown) {
            if (isSystemError(e)) syscrash(e as SystemError);

            else throw e;
        }
    })()
}

if (settings.mode === 'client') {
    client({
        hostname: settings.host,
        port: settings.port,
        passcode: settings.passcode,
        action: (() => {
            if (settings.action === 'send') return {
                type: 'send',
                pipe: 
            }
        })()
    })
}

async function client({ hostname, port, action, validateFP, callback }: {
    hostname: string;
    port: number;
    action: ({
        type: 'send';
        pipe: ((req: http.ClientRequest) => void) | null;
    } | {
        type: 'receive';
        writestream: WriteStream | NodeJS.WriteStream | null;
    })
    validateFP: boolean,
}): Promise<http.ClientRequest> { return new Promise((resolve, reject) => {

    const req = https.request({
        hostname, port,
        path: '/v1/antenna',
        method: 'POST',
        headers: {
            'antenna-version': version(),
            'antenna-action': action.type.toUpperCase(),
            'antenna-hostname': os.hostname()
        }
    })

    req.on('socket', s => s.on('secureConnect', () => {
        
    }))
}}

function crash(errmsg: string, exitcode=1): never {
    console.error(`failure: ${errmsg}`);
    process.exit(exitcode)
}

async function getKeyPair() {
    const configDir = envPaths('antenna-ft').config;
    const privKeyPath = path.join(configDir, 'identity.key');
    const publKeyPath = path.join(configDir, 'identity.pub');

    await fs.mkdir(configDir, { recursive: true });

    const privkey = await (async () => {
        try {
            return fs.readFile(privKeyPath, 'utf8');
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
                    fs.writeFile(privKeyPath, privateKey, 'utf8'),
                    fs.writeFile(publKeyPath, publicKey, 'utf8')
                ]);

                await fs.chmod(privKeyPath, 0o600);

                return privateKey;

            } 

            if (isSystemError(err)) syscrash(err as SystemError);

            else throw err;
        }
    })();

    const publkey = await (async () => {
        try {
            return fs.readFile(publKeyPath, 'utf8');
        } catch (err) {
            if ((err as SystemError)?.code === 'ENOENT') {
                const publicKey = crypto.createPublicKey({
                    key: privkey,  
                    format: 'pem'
                }).export({
                    type: 'spki',
                    format: 'pem'
                });

                await fs.writeFile(publKeyPath, publicKey, 'utf8');

                return publicKey;

            } else throw err;
        }
    })();

    return { publicKey: publkey, privateKey: privkey };
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

function isSystemError(e: unknown) {
    return (e instanceof Error) && (typeof (e as SystemError).code === 'string');
}

function syscrash(e: SystemError): never {
    const error = errno.errno[e.errno];

    if (!error) throw e;

    crash(`${error.description} (${error.code})${e.path && `: ${e.path}`}`);
}


type AppSettings = (
        { 
            mode: 'client';
            host: string;
            port: number;
            passcode: string;
        } | {
            mode: 'server';
            port: number;
            useTsl: boolean;
            usePasscode: boolean;
            multi: boolean;
        }
) & (
        {
            action: 'send';
            readstream: ReadStream | NodeJS.ReadStream;
        } | {
            action: 'receive';
            writestream: WriteStream | NodeJS.WriteStream
        }
)
