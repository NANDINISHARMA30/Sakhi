import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Landing from './Landing';
import Login from './Login';
import UserDashboard from './UserDashboard';
import AdminDashboard from './AdminDashboard';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './App.css';
import VoiceAssistant from './components/voiceassistant';

function App() {
  return (
    <BrowserRouter>
      <div className="App">
        <Routes>
          {/* Landing page */}
          <Route path="/" element={<Landing />} />

          {/* Login page */}
          <Route path="/login" element={<Login />} />

          {/* User Dashboard (after login) */}
          <Route path="/dashboard" element={<UserDashboard />} />

          {/* Admin Dashboard (if needed separately) */}
          <Route path="/admin" element={<AdminDashboard />} />
        </Routes>

        {/* Toast container for success/error messages */}
        <ToastContainer />
        <VoiceAssistant /> {/* ✅ Add Voice Assistant */}
      </div>
    </BrowserRouter>
  );
}

export default App;
