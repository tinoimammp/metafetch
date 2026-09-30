import type { NextPage } from 'next'

const Home: NextPage = () => {
  return (
    <main style={{ fontFamily: 'monospace', maxWidth: 640, margin: '3rem auto', padding: '0 1rem' }}>
      <h1>metafetch</h1>
      <p>Extracts page metadata (title, description, image, favicon…) from a URL.</p>
      <pre style={{ background: '#f4f4f4', padding: '1rem', overflowX: 'auto' }}>
        GET /api/title?url=https://example.com
      </pre>
      <p>
        See <a href="https://github.com/tinoimammp/metafetch">README</a> for the full response schema.
      </p>
    </main>
  )
}

export default Home
