import { Command } from "commander";
import { version } from "./macros";

// @ts-ignore just treat this as any for now
import errno from 'errno'
import fsSync, { ReadStream, WriteStream } from 'fs'
import type { SystemError } from "bun";
import type { Readable } from "stream";

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
    .option('-p, --passive [port]',             "Perform action passively (be the server). Port defaults to 52110", "52110")

    .option('-w, --passcode <passcode>',        "Passcode for authentication (only effective in active mode)")

    .option('-f, --file <path>',                "Which file to read from or write to (defaults to -)", '-')

    .option('-m, --multi',                      "Accept multiple connections. (only effective in passive mode when sending)")
    .option('--no-tsl',                         "Disable TSL encryption. (only effective in passive mode)")
    .option('--no-use-passcode',                "Disable passcode. Note that this break man-in-the-middle attack detection. This allows any regular browsers or HTTP request tools to act as client if used with -Sp")

    .action((options) => {
        XOR('send', 'receive', 'you must specify one and only one of --send and --receive')(options);
        XOR('active', 'passive', 'you must specify one and only one of --active and --passive')(options);
    })
    
parser.parse();

const flags = parser.opts();

const settings: AppSettings = {
    action: flags.send ? 'send' : 'receive',
    mode: flags.active ? 'client' : 'server',
    iostream: await (async () => {
        const { file } = flags;

        if (file === '-') 
            return flags.send ? 
                { type: 'read', readStream: process.stdin } :
                { type: 'write', writeStream: process.stdout };

        try {
            return flags.send ?
                { type: 'read', readStream: fsSync.createReadStream(file) } :
                { type: 'write', writeStream: fsSync.createWriteStream(file) }

        } catch (e: unknown) {
            const syserr = e as SystemError;
            const error = errno.errno[syserr?.errno];

            if (!error) throw e;

            crash(`${error.description} (${error.code})${syserr?.path && `: ${syserr.path}`}`);
        }
    })()
}

function crash(errmsg: string, exitcode=1): never {
    console.error(`failure: ${errmsg}`);
    process.exit(exitcode)
}

function XOR(flag1: string, flag2: string, errmsg: string) {
    return function(options: Record<string, unknown>) {
        if (!!options[flag1] !== !!options[flag2]) return;

        else crash(errmsg);
    }
}

type AppSettings = (
        { 
            mode: 'client'
            host: string;
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
    action: 'send' | 'receive';
    host: string;
    port: number;

    iostream: { type: 'read', readStream: ReadStream | NodeJS.ReadStream }
            | { type: 'write', writeStream: WriteStream | NodeJS.WriteStream };
} | {
    action: 'receive';


})
