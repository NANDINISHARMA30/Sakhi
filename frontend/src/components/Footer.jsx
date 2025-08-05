import React from 'react';
import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="bg-[#283593]/50 backdrop-blur-md pt-16 pb-8 border-t border-white/10">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          <div>
            <h2 className="text-2xl font-bold mb-4">
              <span className="text-[#c5cae9]">Sakhi</span>
            </h2>
            <p className="text-[#e8eaf6] mb-4">
              Finding your perfect roommate has never been easier. Trust Sakhi for safe, compatible matches.
            </p>
            <div className="flex space-x-4">
              {/* Social media icons */}
              {['facebook', 'twitter', 'instagram', 'linkedin'].map((social) => (
                <a key={social} href="#" className="text-[#c5cae9] hover:text-white transition-colors">
                  <span className="sr-only">{social}</span>
                  <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center">
                    {/* Icon placeholder */}
                    <span>@</span>
                  </div>
                </a>
              ))}
            </div>
          </div>
          
          <div>
            <h3 className="text-white font-semibold mb-4">Product</h3>
            <ul className="space-y-2">
              {['Features', 'How it Works', 'Pricing', 'FAQ'].map((item) => (
                <li key={item}>
                  <Link to="#" className="text-[#c5cae9] hover:text-white transition-colors">
                    {item}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          
          <div>
            <h3 className="text-white font-semibold mb-4">Company</h3>
            <ul className="space-y-2">
              {['About Us', 'Team', 'Careers', 'Contact'].map((item) => (
                <li key={item}>
                  <Link to="#" className="text-[#c5cae9] hover:text-white transition-colors">
                    {item}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          
          <div>
            <h3 className="text-white font-semibold mb-4">Legal</h3>
            <ul className="space-y-2">
              {['Terms of Service', 'Privacy Policy', 'Cookie Policy'].map((item) => (
                <li key={item}>
                  <Link to="#" className="text-[#c5cae9] hover:text-white transition-colors">
                    {item}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="pt-8 border-t border-white/10 text-center">
          <p className="text-[#c5cae9]">
            © {new Date().getFullYear()} Sakhi. All rights reserved. Created by Team 404 Girls Found.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;