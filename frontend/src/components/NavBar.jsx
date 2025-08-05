import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

const NavBar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const location = useLocation();
  
  // Function to handle smooth scrolling to sections
  const scrollToSection = (sectionId) => {
    // Close mobile menu if open
    setIsMenuOpen(false);
    
    // If not on home page, navigate to home first then scroll
    if (location.pathname !== '/') {
      window.location.href = `/#${sectionId}`;
      return;
    }
    
    // If already on home page, just scroll
    const section = document.getElementById(sectionId);
    if (section) {
      section.scrollIntoView({ behavior: 'smooth' });
    }
  };
  
  return (
    <header className="bg-[#283593]/50 backdrop-blur-md border-b border-white/10">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link to="/" className="flex items-center">
              <span className="text-2xl font-bold text-white">
                <span className="text-[#c5cae9]">Sakhi</span>
              </span>
            </Link>
          </div>
          
          <nav className="hidden md:flex items-center space-x-8">
            <button 
              onClick={() => scrollToSection('features')} 
              className="text-[#e8eaf6] hover:text-white transition-colors bg-transparent border-none cursor-pointer"
            >
              Features
            </button>
            <button 
              onClick={() => scrollToSection('how-it-works')} 
              className="text-[#e8eaf6] hover:text-white transition-colors bg-transparent border-none cursor-pointer"
            >
              How It Works
            </button>
            <button 
              onClick={() => scrollToSection('about')} 
              className="text-[#e8eaf6] hover:text-white transition-colors bg-transparent border-none cursor-pointer"
            >
              About
            </button>
          </nav>
          
          <div className="hidden md:flex items-center space-x-4">
            <Link to="/login" className="px-4 py-2 text-white hover:text-[#c5cae9] transition-colors">
              Sign In
            </Link>
            <Link 
              to="/register" 
              className="px-4 py-2 bg-white text-[#3949ab] rounded-lg hover:bg-[#e8eaf6] transition-colors font-medium"
            >
              Get Started
            </Link>
          </div>
          
          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="text-white hover:text-[#c5cae9]"
            >
              {isMenuOpen ? (
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              )}
            </button>
          </div>
        </div>
        
        {/* Mobile menu */}
        {isMenuOpen && (
          <div className="md:hidden py-4">
            <div className="flex flex-col space-y-4">
              <button 
                onClick={() => scrollToSection('features')} 
                className="text-[#e8eaf6] hover:text-white transition-colors text-left bg-transparent border-none cursor-pointer"
              >
                Features
              </button>
              <button 
                onClick={() => scrollToSection('how-it-works')} 
                className="text-[#e8eaf6] hover:text-white transition-colors text-left bg-transparent border-none cursor-pointer"
              >
                How It Works
              </button>
              <button 
                onClick={() => scrollToSection('about')} 
                className="text-[#e8eaf6] hover:text-white transition-colors text-left bg-transparent border-none cursor-pointer"
              >
                About
              </button>
              <Link to="/login" className="text-[#e8eaf6] hover:text-white transition-colors">
                Sign In
              </Link>
              <Link 
                to="/register" 
                className="px-4 py-2 bg-white text-[#3949ab] rounded-lg hover:bg-[#e8eaf6] transition-colors inline-block w-max"
              >
                Get Started
              </Link>
            </div>
          </div>
        )}
      </div>
    </header>
  );
};

export default NavBar;