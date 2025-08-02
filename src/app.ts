import { Command } from "commander";
import { version } from "./macros";

// @ts-ignore just treat this as any for now as im too lazy to write declarations
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'
import type { SystemError } from "bun";

import https from 'https';
import http from 'http';

const parser = new Command();

parser
    .name('antenna')
    .usage('(--send | --receive) (--active <host> | --passive [port]) [other options]')
    .description('Quickly and securely transfer file over network with no setup')
    .version(version());
    
parser
    .option('-S, --send',                       "Send file")
    .option('-R, --receive',                    "Receive file")

    .option('-a, --active <host>',              "Perform action actively (be the client)")
    .option('-p, --passive [port]',             "Perform action passively (be the server). Port defaults to 52110", '52110')

    .option('-w, --passcode <passcode>',        "Passcode for authentication (only effective in active mode)")
    .option('--no-mitm-check',                  "Disable man-in-the-middle attack check (only effective in active mode)")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .option('-m, --multi',                      "Accept multiple connections. (only effective in passive mode when sending)")
    .option('--no-tsl',                         "Disable TSL encryption. (only effective in passive mode)")
    .option('--no-use-passcode',                "Disable passcode. Note that this breaks man-in-the-middle attack detection. This allows for any regular browsers or HTTP request tools to act as client if used with -Sp")

    .option('-v, --version',           "Check version information")

    .action((options) => {
        CA_XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        CA_XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
        CA_runIf('version', about)
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
                
            })()
        }

        else return {
            mode: 'server',
            port: flags.passive,
            useTsl: flags.tsl,
            usePasscode: flags.usePasscode,
            multi: flags.multi
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
            const syserr = e as SystemError;
            const error = errno.errno[syserr?.errno];

            if (!error) throw e;

            crash(`${error.description} (${error.code})${syserr?.path && `: ${syserr.path}`}`);
        }
    })()
}

if (settings.mode === 'client') {
    
}

function request(host: string, passcode?: string, stream?: { pipe():void }, tsl=true) {
    const driver = tsl ? https : http;

    driver.request({
        hostname: host,

    })
}

function parseEndpoint(endpoint: string, defaultPort: number): { hostname: string, port?: number } {
    const match = endpoint.match( /^(.+?)(?::([0-9]{1,5}))?$/ );

    if (!match) throw new Error(`Failed to parse endpoint "${endpoint}"`);

    const [ hostname, port ] = match;

    return {
        hostname: match[1],
        port: match[2]!==undefined && parseInt(match[2], 10)
    }
}

function crash(errmsg: string, exitcode=1): never {
    console.error(`failure: ${errmsg}`);
    process.exit(exitcode)
}

function about() {
    console.log(`antenna ${version()}\nReleased under the MIT License by BlackFuffey`);
    process.exit(0);
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
