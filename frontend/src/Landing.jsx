import React from 'react';
import { useNavigate } from 'react-router-dom';
import { NavBar, Footer } from './components';

const Landing = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#283593] via-[#3949ab] to-[#5c6bc0] text-white">
      <NavBar />
      
      <main>
        {/* Hero Section */}
        <section className="container mx-auto px-4 py-16 flex flex-col items-center">
          <div className="text-center max-w-4xl mx-auto mb-12">
            <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
              Find Your Perfect <span className="text-[#c5cae9]">Roommate</span>
            </h1>
            <p className="text-xl text-[#e8eaf6] mb-8 max-w-2xl mx-auto">
              Sakhi helps women find compatible roommates based on lifestyle preferences, making shared living safer and more harmonious.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button 
                onClick={() => navigate('/register')}
                className="sakhi-button-primary"
              >
                Get Started
              </button>
              <button 
                onClick={() => navigate('/login')}
                className="sakhi-button-secondary"
              >
                Learn More
              </button>
            </div>
          </div>
          
          <div className="w-full max-w-4xl">
            <div className="bg-white/10 backdrop-blur-md rounded-2xl overflow-hidden p-1">
              <img 
                src="https://via.placeholder.com/1000x500?text=Sakhi+Platform+Preview" 
                alt="Platform preview" 
                className="w-full h-auto rounded-xl"
              />
            </div>
          </div>
        </section>
        
        {/* Features Section */}
        <section id="features" className="py-16 bg-[#3949ab]/50 scroll-mt-16">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-white">Why Choose Sakhi?</h2>
              <div className="w-20 h-1 bg-[#c5cae9] mx-auto mt-4"></div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {[
                {
                  icon: "🛡️",
                  title: "Safe Community",
                  description: "Women-only community with verified profiles for your peace of mind."
                },
                {
                  icon: "🤝",
                  title: "Perfect Match",
                  description: "Our algorithm matches you with compatible roommates based on your preferences."
                },
                {
                  icon: "💬",
                  title: "Easy Communication",
                  description: "Connect and coordinate with potential roommates in real-time."
                }
              ].map((feature, index) => (
                <div 
                  key={index}
                  className="sakhi-card p-6 text-center"
                >
                  <div className="text-3xl mb-4">{feature.icon}</div>
                  <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-[#e8eaf6]">{feature.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
        
        {/* How It Works Section */}
        <section id="how-it-works" className="py-16 scroll-mt-16">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-white">How It Works</h2>
              <div className="w-20 h-1 bg-[#c5cae9] mx-auto mt-4"></div>
              <p className="text-lg text-[#e8eaf6] max-w-2xl mx-auto mt-4">
                Finding your perfect roommate is just a few simple steps away
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              {[
                {
                  step: "1",
                  title: "Create Profile",
                  description: "Sign up and tell us about your lifestyle, preferences, and roommate expectations."
                },
                {
                  step: "2",
                  title: "Get Matched",
                  description: "Our algorithm finds potential roommates who match your compatibility criteria."
                },
                {
                  step: "3",
                  title: "Connect",
                  description: "Chat with your matches to learn more about each other and see if you click."
                },
                {
                  step: "4",
                  title: "Move In",
                  description: "Finalize your roommate choice and start your harmonious living experience."
                }
              ].map((item, index) => (
                <div key={index} className="sakhi-card p-6 text-center relative">
                  <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                    <div className="w-10 h-10 rounded-full bg-[#7986cb] flex items-center justify-center text-white font-bold">
                      {item.step}
                    </div>
                  </div>
                  <h3 className="text-xl font-semibold text-white mt-4 mb-2">{item.title}</h3>
                  <p className="text-[#e8eaf6]">{item.description}</p>
                </div>
              ))}
            </div>
            
            <div className="mt-12 text-center">
              <button onClick={() => navigate('/register')} className="sakhi-button-primary">
                Start Your Journey
              </button>
            </div>
          </div>
        </section>
        
        {/* About Section */}
        <section id="about" className="py-16 bg-[#3949ab]/50 scroll-mt-16">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-white">About Sakhi</h2>
              <div className="w-20 h-1 bg-[#c5cae9] mx-auto mt-4"></div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div>
                <p className="text-lg text-[#e8eaf6] mb-6">
                  Sakhi is India's first AI-powered roommate matching platform exclusively for women. 
                  We understand the challenges women face in finding safe, compatible living arrangements.
                </p>
                <p className="text-lg text-[#e8eaf6] mb-6">
                  Our mission is to create a trustworthy community where women can find roommates 
                  who match their lifestyle, preferences, and personalities.
                </p>
                <p className="text-lg text-[#e8eaf6]">
                  With advanced algorithms and a focus on safety, we're revolutionizing how women 
                  find their perfect roommates and creating harmonious living situations.
                </p>
              </div>
              
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-6 border border-[#7986cb]/30">
                <h3 className="text-xl font-semibold text-white mb-4">Our Commitment</h3>
                <ul className="space-y-3">
                  {[
                    "Safety and security for all users",
                    "Verification of all profiles",
                    "Privacy protection for sensitive information",
                    "Compatibility-focused matching algorithm",
                    "Supportive community of women"
                  ].map((item, index) => (
                    <li key={index} className="flex items-start">
                      <div className="text-[#c5cae9] mr-2">✓</div>
                      <span className="text-[#e8eaf6]">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </section>
        
        {/* Team Section */}
        <section className="py-16 scroll-mt-16">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <span className="inline-block px-4 py-1 bg-[#7986cb]/50 rounded-full text-[#c5cae9] text-sm font-medium mb-4">Our Team</span>
              <h2 className="text-3xl font-bold text-white">Team 404 Girls Found</h2>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 justify-items-center">
              {['Tanisha', 'Nandini', 'Anshika'].map((member, index) => (
                <div key={index} className="sakhi-card p-6 text-center">
                  <div className="w-20 h-20 rounded-full bg-gradient-to-br from-[#3949ab] to-[#7986cb] mx-auto flex items-center justify-center text-white text-xl font-bold mb-4">
                    {member[0]}
                  </div>
                  <h3 className="text-white font-medium">{member}</h3>
                  <p className="text-[#c5cae9] text-sm">Developer</p>
                </div>
              ))}
            </div>
          </div>
        </section>
        
        {/* CTA Section */}
        <section className="py-16 bg-[#283593]">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-3xl font-bold text-white mb-6">Ready to Find Your Perfect Roommate?</h2>
            <p className="text-xl text-[#e8eaf6] mb-8 max-w-2xl mx-auto">
              Join Sakhi today and start your journey to harmonious co-living.
            </p>
            <button 
              onClick={() => navigate('/register')}
              className="sakhi-button-primary text-lg px-8 py-3"
            >
              Get Started Now
            </button>
          </div>
        </section>
      </main>
      
      <Footer />
    </div>
  );
};

export default Landing;
