import { createFileRoute, useRouter } from '@tanstack/react-router'
import { useState } from 'react'
import { getTodos, addTodo, toggleTodo, deleteTodo } from '../server/todos'
import type { Todo } from '../server/todos'

export const Route = createFileRoute('/')({
  loader: () => getTodos(),
  component: TodoPage,
})

function TodoPage() {
  const todos = Route.useLoaderData()
  const router = useRouter()
  const [title, setTitle] = useState('')
  const [busy, setBusy] = useState(false)

  const refresh = () => router.invalidate()

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim() || busy) return
    setBusy(true)
    try {
      await addTodo({ data: { title } })
      setTitle('')
      refresh()
    } finally {
      setBusy(false)
    }
  }

  const handleToggle = async (id: number) => {
    await toggleTodo({ data: { id } })
    refresh()
  }

  const handleDelete = async (id: number) => {
    await deleteTodo({ data: { id } })
    refresh()
  }

  return (
    <main style={{ maxWidth: 600, margin: '2rem auto' }}>
      <h1>DB2 Todo App</h1>
      <p>
        <small>Powered by db2-node &mdash; pure Rust DRDA driver</small>
      </p>

      <form onSubmit={handleAdd} style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="What needs to be done?"
          disabled={busy}
          style={{ flex: 1 }}
        />
        <button type="submit" disabled={busy || !title.trim()}>
          Add
        </button>
      </form>

      {todos.length === 0 ? (
        <p>
          <em>No todos yet. Add one above!</em>
        </p>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {todos.map((todo: Todo) => (
            <li
              key={todo.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 0',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <input
                type="checkbox"
                checked={todo.completed}
                onChange={() => handleToggle(todo.id)}
              />
              <span
                style={{
                  flex: 1,
                  textDecoration: todo.completed ? 'line-through' : 'none',
                  opacity: todo.completed ? 0.5 : 1,
                }}
              >
                {todo.title}
              </span>
              <button onClick={() => handleDelete(todo.id)}>Delete</button>
            </li>
          ))}
        </ul>
      )}

      <p style={{ marginTop: '2rem', fontSize: '0.85rem', opacity: 0.6 }}>
        {todos.length} todo{todos.length !== 1 ? 's' : ''} &bull; TanStack
        Start + DB2
      </p>
    </main>
  )
}
