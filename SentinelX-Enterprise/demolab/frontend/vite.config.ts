import {defineConfig} from 'vite'
export default defineConfig({server:{proxy:{'/lab':process.env.DEMOLAB_API || 'http://127.0.0.1:8002'}}})
