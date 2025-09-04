import * as ESBuild from 'esbuild';

console.log(await ESBuild.build({
    entryPoints: ['src/antenna.ts'],
    bundle: true,
    platform: 'node',
    treeShaking: true,
    target: [ 'node20' ],
    minify: true,
    format: 'cjs',
    outfile: 'dist/antenna.js',
    external: ['node:events']
}))
