import React from 'react'

export function UserList ({ users, currentUser, onDelete }) {
  return (
    <ul>
      {users.map((user) => (
        <li key={user.id}>
          {user.name}
          {currentUser.role === 'admin' && <button onClick={() => onDelete(user.id)}>Delete</button>}
        </li>
      ))}
    </ul>
  )
}
