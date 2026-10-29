import { Link } from 'react-router-dom'
import { EmptyState } from '../components/EmptyState'
import { Button } from '../components/ui'

export default function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you are looking for does not exist."
      action={
        <Link to="/">
          <Button variant="primary">Back to overview</Button>
        </Link>
      }
    />
  )
}
