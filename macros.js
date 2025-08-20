import fs from 'fs'

export function version() {
    const v = JSON.parse(fs.readSync('package.json')).version;

    if (!v) throw new Error(`Unable to read version from package.json: got ${v}`)
    
    return v
}
