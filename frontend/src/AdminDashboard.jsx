import React, { useState } from 'react';
import { Users, UserPlus, Bell, BarChart2, Settings, CheckCircle, XCircle, Search } from 'lucide-react';
import { ProtectiveShieldBackground } from './components';


const AdminDashboard = () => {
  const [activeSection, setActiveSection] = useState('users');
  
  const users = [
    { id: 1, name: 'Tanisha', email: 'priya@example.com', status: 'active', verified: true },
    { id: 2, name: 'Nandini', email: 'ananya@example.com', status: 'pending', verified: false },
    { id: 3, name: 'Anshika', email: 'meera@example.com', status: 'active', verified: true },
  ];

  const stats = [
    { label: 'Total Users', value: 324, icon: <Users className="w-5 h-5" /> },
    { label: 'Matches Made', value: 156, icon: <UserPlus className="w-5 h-5" /> },
    { label: 'Verification Rate', value: '78%', icon: <CheckCircle className="w-5 h-5" /> },
    { label: 'Active Listings', value: 42, icon: <BarChart2 className="w-5 h-5" /> },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#303f9f] via-[#3949ab] to-[#5c6bc0]">
      <div className="flex h-screen">
        {/* Sidebar */}
        <div className="w-16 md:w-64 bg-[#283593]/70 backdrop-blur-md text-white">
          <div className="p-4 text-center">
            <h1 className="text-xl font-bold hidden md:block">Sakhi Admin</h1>
            <div className="md:hidden mx-auto w-10 h-10 rounded-full bg-[#c5cae9] flex items-center justify-center text-[#3949ab] font-bold">
              S
            </div>
          </div>
          
          <nav className="mt-6 px-2">
            <button 
              onClick={() => setActiveSection('users')} 
              className={`w-full flex items-center p-3 mb-2 rounded-lg ${activeSection === 'users' ? 'bg-[#7986cb]/60' : 'hover:bg-white/10'}`}
            >
              <Users className="w-5 h-5" />
              <span className="hidden md:block ml-3">Users</span>
            </button>
            <button 
              onClick={() => setActiveSection('verifications')} 
              className={`w-full flex items-center p-3 mb-2 rounded-lg ${activeSection === 'verifications' ? 'bg-[#7986cb]/60' : 'hover:bg-white/10'}`}
            >
              <CheckCircle className="w-5 h-5" />
              <span className="hidden md:block ml-3">Verifications</span>
            </button>
            <button 
              onClick={() => setActiveSection('analytics')} 
              className={`w-full flex items-center p-3 mb-2 rounded-lg ${activeSection === 'analytics' ? 'bg-[#7986cb]/60' : 'hover:bg-white/10'}`}
            >
              <BarChart2 className="w-5 h-5" />
              <span className="hidden md:block ml-3">Analytics</span>
            </button>
            <button 
              onClick={() => setActiveSection('settings')} 
              className={`w-full flex items-center p-3 mb-2 rounded-lg ${activeSection === 'settings' ? 'bg-[#7986cb]/60' : 'hover:bg-white/10'}`}
            >
              <Settings className="w-5 h-5" />
              <span className="hidden md:block ml-3">Settings</span>
            </button>
          </nav>
        </div>
        
        {/* Main Content */}
        <div className="flex-1 overflow-auto">
          {/* Header */}
          <header className="bg-white/10 backdrop-blur-md p-4">
            <div className="flex justify-between items-center">
              <h1 className="text-xl font-bold text-white">Dashboard</h1>
              <div className="flex items-center space-x-4">
                <button className="p-2 rounded-full bg-white/10 hover:bg-white/20 transition-all relative">
                  <Bell className="w-5 h-5 text-white" />
                  <span className="absolute -top-1 -right-1 w-4 h-4 bg-[#7986cb] rounded-full text-xs flex items-center justify-center">2</span>
                </button>
                <div className="flex items-center space-x-2">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[#7986cb] to-[#c5cae9] flex items-center justify-center text-[#3949ab] font-bold">
                    A
                  </div>
                  <span className="text-sm text-white hidden md:block">Admin</span>
                </div>
              </div>
            </div>
          </header>
          
          {/* Dashboard Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 p-6">
            {stats.map((stat, index) => (
              <div key={index} className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-[#7986cb]/30">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="text-[#c5cae9]">{stat.label}</p>
                    <h3 className="text-2xl font-bold text-white">{stat.value}</h3>
                  </div>
                  <div className="p-3 bg-[#7986cb]/30 rounded-full">
                    {stat.icon}
                  </div>
                </div>
              </div>
            ))}
          </div>
          
          {/* Users Table */}
          {activeSection === 'users' && (
            <div className="p-6">
              <div className="bg-white/10 backdrop-blur-sm rounded-lg overflow-hidden border border-[#7986cb]/30">
                <div className="p-4 flex justify-between items-center border-b border-white/10">
                  <h2 className="text-lg font-semibold text-white">Users</h2>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Search users..."
                      className="pl-10 pr-4 py-2 bg-white/5 border border-[#7986cb]/30 rounded-lg text-white placeholder-white/50 focus:outline-none focus:border-[#c5cae9]"
                    />
                    <Search className="absolute left-3 top-2.5 w-4 h-4 text-white/50" />
                  </div>
                </div>
                <table className="w-full text-white">
                  <thead className="bg-[#3949ab]/50">
                    <tr>
                      <th className="py-3 px-4 text-left">Name</th>
                      <th className="py-3 px-4 text-left">Email</th>
                      <th className="py-3 px-4 text-left">Status</th>
                      <th className="py-3 px-4 text-left">Verified</th>
                      <th className="py-3 px-4 text-left">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user) => (
                      <tr key={user.id} className="border-b border-white/10 hover:bg-white/5">
                        <td className="py-3 px-4">{user.name}</td>
                        <td className="py-3 px-4">{user.email}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            user.status === 'active' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            {user.status}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {user.verified ? 
                            <CheckCircle className="w-5 h-5 text-green-400" /> : 
                            <XCircle className="w-5 h-5 text-red-400" />
                          }
                        </td>
                        <td className="py-3 px-4">
                          <button className="text-[#c5cae9] hover:underline">Edit</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          
          {/* Other sections would go here */}
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;