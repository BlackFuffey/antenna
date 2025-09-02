import * as ESBuild from 'esbuild';

console.log(await ESBuild.build({
    entryPoints: ['src/antenna.ts'],
    bundle: true,
    platform: 'node',
    treeShaking: true,
    target: [ 'node20' ],
    minify: true,
    format: 'esm',
    outfile: 'dist/antenna.js',
}))
