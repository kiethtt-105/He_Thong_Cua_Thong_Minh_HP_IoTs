import { useState } from 'react';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  'https://your-project.supabase.co',
  'your-anon-key'
);

function App() {
  const [page, setPage] = useState('home');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // Giả lập đăng nhập
  const handleLogin = async () => {
    const { error } = await supabase.auth.signInWithPassword({ email: 'owner@example.com', password: '123456' });
    if (!error) setIsLoggedIn(true);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-blue-600 text-white p-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <h1 className="text-3xl font-bold">Smart Lock IoT</h1>
          <div>
            <button onClick={() => setPage('devices')} className="mr-6">Devices</button>
            <button onClick={() => setPage('nfc')} className="mr-6">NFC Scan</button>
            <button onClick={() => setPage('commands')}>Commands</button>
            <button onClick={handleLogin} className="ml-6 bg-white text-blue-600 px-4 py-2 rounded">Login / Register</button>
          </div>
        </div>
      </nav>

      <div className="p-8 max-w-7xl mx-auto">
        {page === 'devices' && <Devices />}
        {page === 'nfc' && <NFCScan />}
        {page === 'commands' && <Commands />}
      </div>
    </div>
  );
}

export default App;

// Các component con (Devices, NFCScan, Commands) có thể thêm sauimport { useState } from 'react';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  'https://your-project.supabase.co',
  'your-anon-key'
);

function App() {
  const [page, setPage] = useState('home');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // Giả lập đăng nhập
  const handleLogin = async () => {
    const { error } = await supabase.auth.signInWithPassword({ email: 'owner@example.com', password: '123456' });
    if (!error) setIsLoggedIn(true);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-blue-600 text-white p-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <h1 className="text-3xl font-bold">Smart Lock IoT</h1>
          <div>
            <button onClick={() => setPage('devices')} className="mr-6">Devices</button>
            <button onClick={() => setPage('nfc')} className="mr-6">NFC Scan</button>
            <button onClick={() => setPage('commands')}>Commands</button>
            <button onClick={handleLogin} className="ml-6 bg-white text-blue-600 px-4 py-2 rounded">Login / Register</button>
          </div>
        </div>
      </nav>

      <div className="p-8 max-w-7xl mx-auto">
        {page === 'devices' && <Devices />}
        {page === 'nfc' && <NFCScan />}
        {page === 'commands' && <Commands />}
      </div>
    </div>
  );
}

export default App;

// Các component con (Devices, NFCScan, Commands) có thể thêm sau