import {defineConfig} from 'vite'
export default defineConfig({
  server: {proxy: {'/api': {target: process.env.SENTINELX_API || 'http://127.0.0.1:8003', timeout: 0, proxyTimeout: 0}}}
})
