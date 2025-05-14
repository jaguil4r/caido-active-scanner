const esbuild = require('esbuild');
const path = require('path');

const isWatch = process.argv.includes('--watch');

const commonOptions = {
  entryPoints: [path.resolve(__dirname, 'backend/index.ts')],
  bundle: true,
  outfile: path.resolve(__dirname, 'dist/backend/index.js'),
  platform: 'node', // or 'browser' if targeting browser-like envs in Caido
  format: 'esm', // Caido backend uses ESM
  target: 'es2020',
  external: ['@caido/sdk-backend'], // Externalize Caido SDK
  sourcemap: true, // Optional: for easier debugging
  minify: !isWatch, // Minify only for production builds
};

async function run() {
  if (isWatch) {
    console.log('Initializing esbuild in watch mode...');
    try {
      const ctx = await esbuild.context({
        ...commonOptions,
        logLevel: 'info', // Provides feedback on rebuilds
      });
      await ctx.watch();
      console.log('Watching for changes in backend...');
      // Keep the script running for watch mode
      // This can be done by not exiting, or a more complex setup if needed
      // For now, letting it hang here is fine for esbuild watch
    } catch (e) {
      console.error('esbuild watch failed:', e);
      process.exit(1);
    }
  } else {
    console.log('Running esbuild production build...');
    try {
      await esbuild.build({
        ...commonOptions,
      });
      console.log('Backend build successful.');
    } catch (e) {
      console.error('esbuild build failed:', e);
      process.exit(1);
    }
  }
}

run(); 