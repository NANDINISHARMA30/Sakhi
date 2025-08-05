import React, { useState, useRef, useEffect } from 'react';
import { Shield, CheckCircle, AlertCircle, MapPin, Edit, Camera, Bell, User, Send } from 'lucide-react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';  // <-- import useNavigate

const matchesData = [
  { id: 1, name: 'Tanisha', score: 92, room: 'Room 102, Sunny Side', verified: true },
  { id: 2, name: 'Nandini', score: 85, room: 'Room 305, Quiet Corner', verified: false },
  { id: 3, name: 'Anshika', score: 78, room: 'Room 201, City View', verified: true },
];

const messagesList = [
  { id: 1, user: 'Tanisha', lastMsg: 'Hey, when do you want to meet up?', time: '1h ago', unread: true },
  { id: 2, user: 'Nandini', lastMsg: 'Loved chatting with you! 😊', time: '3h ago', unread: false },
  { id: 3, user: 'Anshika', lastMsg: 'Let’s prepare for the roommate meet.', time: 'Yesterday', unread: false },
];

const mockChats = {
  1: [
    { fromUser: true, text: 'Hi! 😊 Nice to meet you.' },
    { fromUser: false, text: 'Same here! Want to grab coffee?' },
    { fromUser: true, text: 'Sure. How about tomorrow?' },
  ],
  2: [
    { fromUser: true, text: 'Hey Nandini! Your interests look fun.' },
    { fromUser: false, text: 'Thank you! Let’s chat more.' },
    { fromUser: true, text: 'Anytime. 😊' },
  ],
  3: [
    { fromUser: false, text: 'Meet tomorrow at the lounge?' },
    { fromUser: true, text: 'Sounds good! Looking forward 👍' },
  ],
};

const notifications = [
  { id: 1, type: 'info', message: "You've been matched with Tanisha", time: '10 minutes ago' },
  { id: 2, type: 'alert', message: 'Upcoming Roommate Meet on August 5', time: '2 hours ago' },
  { id: 3, type: 'success', message: 'Application survey submitted successfully!', time: 'Yesterday' },
];

const iconMap = {
  info: <Bell className="w-5 h-5 text-blue-400 mr-2" />,
  alert: <AlertCircle className="w-5 h-5 text-yellow-400 mr-2" />,
  success: <CheckCircle className="w-5 h-5 text-green-400 mr-2" />,
};

const UserDashboard = () => {
  const navigate = useNavigate(); // <-- initialize navigate

  useEffect(() => {
    const script = document.createElement('script');
    script.id = 'omnidimension-web-widget';
    script.async = true;
    script.src = "https://backend.omnidim.io/web_widget.js?secret_key=e99bc6cd0df6f150c04accc866dbc39d";
    document.body.appendChild(script);
    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const notificationRef = useRef(null);
  const profileRef = useRef(null);
  const [showNotificationsDropdown, setShowNotificationsDropdown] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const [activeTab, setActiveTab] = useState('matches');
  const [matchStatuses, setMatchStatuses] = useState({});
  const [selectedMsg, setSelectedMsg] = useState(messagesList[0]);
  const [typedMsg, setTypedMsg] = useState('');
  const [chatData, setChatData] = useState(mockChats);

  const handleAcceptMatch = (matchId) =>
    setMatchStatuses((prev) => ({ ...prev, [matchId]: 'accepted' }));
  const handleRejectMatch = (matchId) =>
    setMatchStatuses((prev) => ({ ...prev, [matchId]: 'rejected' }));
  const getMatchStatus = (matchId) => matchStatuses[matchId] || 'pending';

  const handleSend = () => {
    if (!typedMsg.trim() || !selectedMsg) return;
    setChatData({
      ...chatData,
      [selectedMsg.id]: [...(chatData[selectedMsg.id] || []), { fromUser: true, text: typedMsg }],
    });
    setTypedMsg('');
  };

  // New function: handle sign out and navigate to main page
  const handleSignOut = () => {
    // Clear any auth tokens or user data if applicable, e.g.:
    // localStorage.removeItem('authToken');
    // sessionStorage.clear();

    navigate('/'); // Adjust path to your main or login page route
  };

  useEffect(() => {
    function handleClickOutside(event) {
      if (
        notificationRef.current &&
        !notificationRef.current.contains(event.target) &&
        showNotificationsDropdown
      ) {
        setShowNotificationsDropdown(false);
      }
      if (
        profileRef.current &&
        !profileRef.current.contains(event.target) &&
        showProfile
      ) {
        setShowProfile(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showNotificationsDropdown, showProfile]);

  return (
    <div className="relative min-h-screen w-full overflow-hidden text-white bg-gradient-to-b from-blue-700 via-blue-800 to-blue-900">
      {/* Removed ProtectiveShieldBackground component as per request */}

      <div className="relative z-10 max-w-7xl mx-auto p-6">
        {/* Navbar */}
        <motion.nav
          initial={{ y: -80, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="fixed top-0 left-0 w-full bg-black/20 backdrop-blur-xl shadow-lg z-20 border-b border-blue-400/20"
        >
          <div className="max-w-7xl mx-auto px-4">
            <div className="flex items-center justify-between h-16">
              {/* Left - Only Title */}
              <div className="flex items-center space-x-3">
                <span className="text-2xl font-extrabold text-blue-400 tracking-tight drop-shadow-lg">
                  Saakhi
                </span>
              </div>
              {/* Center - Tabs */}
              <div className="flex space-x-3">
                <button
                  onClick={() => setActiveTab('matches')}
                  className={`px-4 py-2 rounded font-semibold ${
                    activeTab === 'matches'
                      ? 'bg-blue-400 text-white'
                      : 'bg-transparent hover:bg-blue-400/20 text-blue-200'
                  }`}
                >
                  Matches
                </button>
                <button
                  onClick={() => setActiveTab('messages')}
                  className={`px-4 py-2 rounded font-semibold ${
                    activeTab === 'messages'
                      ? 'bg-blue-400 text-white'
                      : 'bg-transparent hover:bg-blue-400/20 text-blue-200'
                  }`}
                >
                  Messages
                </button>
                <button
                  onClick={() => setActiveTab('notifications')}
                  className={`px-4 py-2 rounded font-semibold ${
                    activeTab === 'notifications'
                      ? 'bg-blue-400 text-white'
                      : 'bg-transparent hover:bg-blue-400/20 text-blue-200'
                  }`}
                >
                  Notifications
                </button>
              </div>
              {/* Right side actions */}
              <div className="flex items-center space-x-4">
                <div className="text-white text-sm">
                  Hi, <span className="font-medium">UserName</span>
                </div>
                {/* Bell Dropdown */}
                <div className="relative" ref={notificationRef}>
                  <button
                    onClick={() => setShowNotificationsDropdown(!showNotificationsDropdown)}
                    className="text-white hover:text-blue-200 p-2 rounded-full hover:bg-blue-600 transition-colors duration-200"
                  >
                    <Bell size={20} />
                  </button>
                  {showNotificationsDropdown && (
                    <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-10">
                      <div className="px-4 py-2 text-sm text-gray-700">No new notifications</div>
                    </div>
                  )}
                </div>
                {/* Profile Dropdown */}
                <div className="relative" ref={profileRef}>
                  <button
                    onClick={() => setShowProfile(!showProfile)}
                    className="flex items-center justify-center w-8 h-8 bg-blue-500 hover:bg-blue-600 rounded-full transition-colors duration-200"
                  >
                    <User size={18} className="text-white" />
                  </button>
                  {showProfile && (
                    <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-10">
                      <a href="#" className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                        Profile
                      </a>
                      <a href="#" className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                        Settings
                      </a>
                      {/* Changed Sign out to button to handle onClick */}
                      <button
                        onClick={handleSignOut}
                        className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                      >
                        Sign out
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </motion.nav>

        {/* Rest of your dashboard content remains fully unchanged */}
        {/* Matches, Messages, Notifications tabs here */}
        <div className="pt-28">
          {activeTab === 'matches' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Matches content */}
              <div className="col-span-2 space-y-4">
                <h2 className="text-xl font-semibold">Your Top Matches</h2>
                {matchesData.map((match) => (
                  <div
                    key={match.id}
                    className="p-4 rounded-lg bg-slate-800/60 backdrop-blur-sm border border-blue-400/20 hover:border-blue-400/40 transition"
                  >
                    <div className="flex justify-between items-center">
                      <div className="flex items-center space-x-3">
                        <div className="relative">
                          <img
                            src={`https://via.placeholder.com/50?text=${match.name[0]}`}
                            alt={match.name}
                            className="w-12 h-12 rounded-full"
                          />
                          {match.verified && (
                            <CheckCircle className="absolute -bottom-1 -right-1 w-5 h-5 text-emerald-400" />
                          )}
                        </div>
                        <div>
                          <h3 className="font-medium">{match.name}</h3>
                          <p className="text-sm text-gray-300 flex items-center">
                            <MapPin className="w-3 h-3 mr-1" />
                            {match.room}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-lg font-bold text-blue-400">{match.score}% Match</p>
                        {getMatchStatus(match.id) === 'pending' && (
                          <div className="flex space-x-2 mt-2">
                            <button
                              onClick={() => handleAcceptMatch(match.id)}
                              className="px-4 py-1 text-sm rounded-full bg-green-500 hover:bg-green-600 transition text-white font-medium"
                            >
                              Accept
                            </button>
                            <button
                              onClick={() => handleRejectMatch(match.id)}
                              className="px-4 py-1 text-sm rounded-full bg-red-500 hover:bg-red-600 transition text-white font-medium"
                            >
                              Reject
                            </button>
                          </div>
                        )}
                        {getMatchStatus(match.id) === 'accepted' && (
                          <div className="mt-2">
                            <span className="px-3 py-1 text-sm rounded-full bg-green-500/20 text-green-400 border border-green-400/30">
                              ✓ Accepted
                            </span>
                          </div>
                        )}
                        {getMatchStatus(match.id) === 'rejected' && (
                          <div className="mt-2">
                            <span className="px-3 py-1 text-sm rounded-full bg-red-500/20 text-red-400 border border-red-400/30">
                              ✗ Rejected
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                    <button className="mt-2 text-sm text-blue-300 hover:underline flex items-center">
                      <Camera className="w-4 h-4 mr-1" /> View Virtual Tour
                    </button>
                  </div>
                ))}
                <button className="text-sm text-blue-300 hover:underline">Request Re-Matching</button>
              </div>
              {/* Profile & Notifications Section */}
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-slate-800/60 backdrop-blur-sm border border-blue-400/20">
                  <h2 className="text-lg font-semibold mb-3">Match Summary</h2>
                  <div className="grid grid-cols-3 gap-2 text-sm">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-400">
                        {matchesData.filter((m) => getMatchStatus(m.id) === 'pending').length}
                      </div>
                      <div className="text-gray-300">Pending</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-400">
                        {matchesData.filter((m) => getMatchStatus(m.id) === 'accepted').length}
                      </div>
                      <div className="text-gray-300">Accepted</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-red-400">
                        {matchesData.filter((m) => getMatchStatus(m.id) === 'rejected').length}
                      </div>
                      <div className="text-gray-300">Rejected</div>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-slate-800/60 backdrop-blur-sm border border-blue-400/20">
                  <h2 className="text-lg font-semibold mb-2">Your Preferences</h2>
                  <ul className="text-sm space-y-1">
                    <li>Sleep: Late Night</li>
                    <li>Cleanliness: Moderate</li>
                    <li>Social Energy: Low</li>
                  </ul>
                  <button className="mt-3 text-sm text-blue-300 hover:underline flex items-center">
                    <Edit className="w-4 h-4 mr-1" /> Edit Preferences
                  </button>
                </div>
                <div className="p-4 rounded-lg bg-slate-800/60 backdrop-blur-sm border border-blue-400/20">
                  <h2 className="text-lg font-semibold mb-2">Application Status</h2>
                  <p className="text-sm">Survey Completed: ✅</p>
                  <p className="text-sm">Match Pending: ⏳</p>
                  <p className="text-sm text-blue-300">Complete your profile for better matches!</p>
                </div>
                <div className="p-4 rounded-lg bg-slate-800/60 backdrop-blur-sm border border-blue-400/20">
                  <h2 className="text-lg font-semibold mb-2 flex items-center">
                    <Shield className="w-5 h-5 mr-2" /> Safety Tools
                  </h2>
                  <button className="text-sm text-blue-300 hover:underline">Report Issue</button>
                  <p className="text-sm mt-2">Emergency Contact: Available</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'messages' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Messages content */}
              <div className="md:col-span-1 bg-slate-900/70 p-4 rounded-lg max-h-[530px] overflow-y-auto">
                {messagesList.map((msg) => (
                  <div
                    key={msg.id}
                    onClick={() => setSelectedMsg(msg)}
                    className={`flex items-center p-3 rounded-lg cursor-pointer mb-2 transition ${
                      selectedMsg?.id === msg.id ? 'blue-700/40' : 'hover:bg-slate-700/30'
                    }`}
                  >
                    <div className="w-10 h-10 rounded-full bg-blue-500 flex items-center justify-center mr-3 text-lg font-bold">
                      {msg.user[0]}
                    </div>
                    <div className="flex-grow">
                      <div className="font-medium text-blue-200">{msg.user}</div>
                      <div className="text-xs text-gray-300 truncate">{msg.lastMsg}</div>
                    </div>
                    {msg.unread && <div className="ml-2 w-2 h-2 rounded-full bg-blue-400" />}
                  </div>
                ))}
              </div>
              <div className="md:col-span-2 bg-slate-900/70 p-4 rounded-lg flex flex-col h-[500px]">
                {selectedMsg ? (
                  <>
                    <div className="flex items-center mb-3">
                      <User className="w-6 h-6 mr-2 text-blue-200" />
                      <span className="font-semibold">{selectedMsg.user}</span>
                      <span className="ml-auto text-xs text-gray-400">{selectedMsg.time}</span>
                    </div>
                    <div className="flex-1 overflow-y-auto mb-4 pr-2">
                      {(chatData[selectedMsg.id] || []).map((chat, idx) =>
                        chat.fromUser ? (
                          <div key={idx} className="mb-2 flex justify-end">
                            <div className="bg-violet-500/80 p-2 rounded-bl-lg rounded-br-lg rounded-tl-lg text-sm max-w-xs">
                              {chat.text}
                            </div>
                          </div>
                        ) : (
                          <div key={idx} className="mb-2 flex">
                            <div className="bg-blue-600/80 p-2 rounded-bl-lg rounded-br-lg rounded-tr-lg text-sm max-w-xs">
                              {chat.text}
                            </div>
                          </div>
                        )
                      )}
                    </div>
                    <div className="flex items-center">
                      <input
                        type="text"
                        className="w-full px-3 py-2 rounded-l-lg bg-slate-800 text-white focus:outline-none"
                        placeholder="Type your message..."
                        value={typedMsg}
                        onChange={(e) => setTypedMsg(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSend();
                        }}
                      />
                      <button
                        className="bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded-r-lg"
                        onClick={handleSend}
                        disabled={!typedMsg.trim()}
                      >
                        <Send className="w-5 h-5" />
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="text-gray-400 flex-1 flex items-center justify-center">
                    Select a conversation to start chatting.
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="bg-slate-900/70 rounded-lg p-6 max-w-xl mx-auto shadow-lg space-y-4">
              <h2 className="text-2xl font-bold mb-4 text-blue-300">Notifications</h2>
              {notifications.length === 0 ? (
                <div className="text-gray-400 text-center">No new notifications.</div>
              ) : (
                notifications.map((note) => (
                  <div
                    key={note.id}
                    className="flex items-center border-l-4 pl-3 py-2 text-sm mb-1 bg-slate-800/60 rounded border-blue-400/40"
                  >
                    {iconMap[note.type]}
                    <span className="flex-1">{note.message}</span>
                    <span className="ml-4 text-xs text-gray-400">{note.time}</span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UserDashboard;
