await Bun.build({
    entrypoints: ['./src/antenna.ts'],
    outdir: './dist',
    target: 'bun',
    format: 'esm',
    minify: true,
})
