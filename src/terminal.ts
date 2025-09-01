import tty from 'tty';
import fs from 'fs/promises';
import readline from 'readline'

const ttyfile = await fs.open('/dev/tty', 'r+');
const input = new tty.ReadStream(ttyfile.fd);
const output = new tty.WriteStream(ttyfile.fd);

let lineLocked = false;

const terminal = {
    async print(msg: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const ok = output.write(msg, (err) => {
                if (err) reject(err);
            });
            if (ok) {
                resolve(); // flushed immediately
            } else {
                output.once('drain', resolve); // wait until buffer drains
            }
        });
    },
    
    async println(msg: string): Promise<void> {
        return terminal.print(`${msg}\n`)
    },

    async ask(msg: string): Promise<string> {
        const rl = readline.createInterface({ input, output });

        return new Promise(resolve => {
            lineLocked = true;
            rl.question(msg, answer => {
                rl.close();
                lineLocked = false;
                resolve(answer);
            });
        });
    },

    spin(msg: string) {
        const { spin, success, failure } = {
            success: ' ✔',
            failure: ' ✘',
            spin: {
                frames: [' ■', ' □'],
                interval: 500
            }
        };

        let finished = false;
        let error = false;
        let finishSpin: ()=>void = () => {
            throw new Error('Attempted to conclude spin before resolver is set')
        };

        const spinController: {
            resolve: ()=>Promise<void>;
            reject: ()=>Promise<void>;
            promise: Promise<void>;
            setline: (newmsg: string)=>void;
        } = {
            resolve: () => { throw new Error('Attempted to stop spin before resolver is set') },    
            reject: () => { throw new Error('Attempted to error spin before resolver is set') },
            promise: new Promise<void>(resolve => finishSpin = resolve),
            setline: (newmsg) => msg = newmsg
        };

        new Promise<void>((resolve, reject) => {
            spinController.resolve = () => {
                resolve();
                return spinController.promise;
            };
            spinController.reject = () => {
                reject();
                return spinController.promise;
            };
        }).catch(() => error = true).finally(() => finished = true);

        (async () => {
            let atFrame = 0;

            while (!finished) {
                if (!lineLocked) {
                    readline.clearLine(output, 0);
                    readline.cursorTo(output, 0);

                    output.write(msg.replace('%spin%', spin.frames[atFrame]!));

                    atFrame++;
                    if (atFrame >= spin.frames.length)
                        atFrame = 0;
                }

                await new Promise(resolve => setTimeout(resolve, spin.interval));
            }

            readline.clearLine(output, 0);
            readline.cursorTo(output, 0);

            if (!error)
                output.write(msg.replace(
                    '%spin%', `\x1b[32m${success}\x1b[0m`
                ) + '\n')

            else 
                output.write(msg.replace(
                    '%spin%', `\x1b[31m${failure}\x1b[0m`
                ) + '\n');

            finishSpin();
        })();

        return spinController;
    }
}

export default terminal;
