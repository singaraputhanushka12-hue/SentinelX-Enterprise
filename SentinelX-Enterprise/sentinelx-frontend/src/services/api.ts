import axios from 'axios'
export async function api<T>(path: string, body?: object): Promise<T> {
  try {
    const response = body === undefined ? await axios.get<T>(path) : await axios.post<T>(path, body)
    return response.data
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const detail = error.response?.data?.detail
      if (typeof detail === 'string') throw new Error(detail)
      if (Array.isArray(detail)) throw new Error(detail.map(issue => issue.msg).join('. '))
      throw new Error(error.response ? 'Request failed (HTTP ' + error.response.status + ')' : 'The server is unavailable')
    }
    throw error
  }
}
export const date = (value: number) => new Date(value * 1000).toLocaleString()
export const label = (value: string) => value.replaceAll('_', ' ')

