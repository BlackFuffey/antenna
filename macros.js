import fs from 'fs'

export function version() {
    const v = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;

    if (!v) throw new Error(`Unable to read version from package.json: got ${v}`)
    
    return v
}
