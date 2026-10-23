import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';
import { Landing } from './pages/Landing';
import { Ingest } from './pages/Ingest';
import { Dashboard } from './pages/Dashboard';
import { SystemStatusIndicator } from './components/SystemStatusIndicator';
import { ErrorBoundary } from './components/ErrorBoundary';

function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/ingest" element={<Ingest />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ErrorBoundary>

      {/* Global unobtrusive microservice health indicator */}
      <SystemStatusIndicator />

      {/* Dark-themed Sonner Toaster */}
      <Toaster
        theme="dark"
        position="bottom-right"
        richColors={false}
        closeButton={false}
        toastOptions={{
          style: {
            background: '#0c0e17',
            border: '1px solid #1e293b',
            color: '#f8fafc',
            fontFamily: 'var(--font-sans)',
            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)',
          },
          className: 'text-xs font-sans',
        }}
      />
    </BrowserRouter>
  );
}

export default App;
