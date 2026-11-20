import {useCallback, useEffect, useState} from 'react'
import {api} from '../services/api'
export function useData<T>(path: string, refreshMs?: number) {
  const [result, setResult] = useState<{path: string; data?: T; error?: string}>({path: ''})
  const [version, setVersion] = useState(0)
  useEffect(() => {
    let current = true
    api<T>(path).then(data => {if (current) setResult({path, data})})
      .catch(error => {if (current) setResult({path, error: error.message})})
    return () => {current = false}
  }, [path, version])
  const reload = useCallback(() => setVersion(value => value + 1), [])
  useEffect(() => {
    if (!refreshMs) return
    const timer = window.setInterval(reload, refreshMs)
    return () => window.clearInterval(timer)
  }, [refreshMs, reload])
  return {...(result.path === path ? result : {data: undefined, error: undefined}),
    reload}
}

