import { createServerFn } from '@tanstack/react-start'
import { getClient } from '../db'

export type Todo = {
  id: number
  title: string
  completed: boolean
  createdAt: string
}

export const getTodos = createServerFn().handler(async () => {
  const db = await getClient()
  const result = await db.query(
    'SELECT id, title, completed, created_at FROM todos ORDER BY created_at DESC',
  )
  return result.rows.map((row: any) => ({
    id: Number(row.ID),
    title: String(row.TITLE),
    completed: Number(row.COMPLETED) === 1,
    createdAt: String(row.CREATED_AT),
  })) as Todo[]
})

export const addTodo = createServerFn({ method: 'POST' })
  .inputValidator((d: { title: string }) => {
    if (!d.title || !d.title.trim()) throw new Error('Title is required')
    return { title: d.title.trim() }
  })
  .handler(async ({ data }) => {
    const db = await getClient()
    await db.query('INSERT INTO todos (title) VALUES (?)', [data.title])
  })

export const toggleTodo = createServerFn({ method: 'POST' })
  .inputValidator((d: { id: number }) => d)
  .handler(async ({ data }) => {
    const db = await getClient()
    await db.query(
      'UPDATE todos SET completed = CASE WHEN completed = 0 THEN 1 ELSE 0 END WHERE id = ?',
      [data.id],
    )
  })

export const deleteTodo = createServerFn({ method: 'POST' })
  .inputValidator((d: { id: number }) => d)
  .handler(async ({ data }) => {
    const db = await getClient()
    await db.query('DELETE FROM todos WHERE id = ?', [data.id])
  })
