import type { TsdownPlugin } from 'tsdown'
import { readdirSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { defineConfig } from 'tsdown'

const root = resolve(dirname(fileURLToPath(import.meta.url)))
const outputDirectory = join(root, 'lib')
let buildGeneration = 0

interface IntegrityManifest {
  format: string
  version: number
  files: Record<string, string>
}

interface IntegrityModule {
  MANIFEST_FILE: string
  computeIntegrityManifest: (baseDir: string, relativeFiles: string[]) => IntegrityManifest
}

function collectFiles(directory: string): string[] {
  const files: string[] = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...collectFiles(path))
    else if (entry.isFile()) files.push(path)
  }
  return files
}

function integrityManifestPlugin(): TsdownPlugin {
  return {
    name: 'dsh-encrypt-integrity-manifest',
    async closeBundle(error): Promise<void> {
      if (error) return
      const moduleUrl = pathToFileURL(join(outputDirectory, 'integrity.js'))
      moduleUrl.searchParams.set('build', String(buildGeneration++))
      const integrity = (await import(moduleUrl.href)) as IntegrityModule
      const relativeFiles = collectFiles(outputDirectory)
        .map(path => relative(root, path).split(sep).join('/'))
        .filter(path => path !== `lib/${integrity.MANIFEST_FILE}`)
      relativeFiles.push('cordis.patch.yml')
      const manifest = integrity.computeIntegrityManifest(root, relativeFiles)
      writeFileSync(join(outputDirectory, integrity.MANIFEST_FILE), `${JSON.stringify(manifest, null, 2)}\n`)
      console.log(`dsh-encrypt: integrity manifest written for ${relativeFiles.length} shipped files`)
    },
  }
}

export default defineConfig({
  entry: {
    client: 'src/client.ts',
    compat: 'src/compat.ts',
    index: 'src/index.ts',
    integrity: 'src/integrity.ts',
    'leak-guard': 'src/leak-guard.ts',
    lockout: 'src/lockout.ts',
    trust: 'src/trust.ts',
    vault: 'src/vault.ts',
    web: 'src/web.ts',
  },
  clean: true,
  dts: {
    generator: 'oxc',
  },
  fixedExtension: false,
  format: 'esm',
  outDir: 'lib',
  platform: 'node',
  plugins: [integrityManifestPlugin()],
  sourcemap: true,
  target: 'es2022',
  tsconfig: 'tsconfig.build.json',
})
