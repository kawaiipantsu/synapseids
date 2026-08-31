import { StreamProvider } from './api/stream'
import { Shell } from './components/Shell'

export default function App() {
  return (
    <StreamProvider>
      <Shell />
    </StreamProvider>
  )
}
