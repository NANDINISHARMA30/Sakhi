import React from 'react';
import { Shield } from 'lucide-react';

const ProtectiveShieldBackground = () => {
  return (
    <div className="relative w-full h-full overflow-hidden bg-gradient-to-br from-slate-900 via-blue-900 to-bluek-900">
      {/* Primary gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-tr from-blue-950/80 via-rose-900/60 to-blue-950/90"></div>
      
      {/* Main Shield Network Grid */}
      <div className="absolute inset-0">
        {[...Array(8)].map((_, i) => (
          <div
            key={`main-shield-${i}`}
            className="absolute"
            style={{
              left: `${20 + (i % 3) * 30}%`,
              top: `${20 + Math.floor(i / 3) * 25}%`,
              animation: `shieldPulse ${4 + i * 0.5}s ease-in-out infinite ${i * 0.3}s`
            }}
          >
            <div className="relative">
              <Shield className="w-20 h-20 text-blue-400/50 drop-shadow-lg" />
              <div className="absolute inset-0 bg-blue-400/20 rounded-full blur-xl scale-150 animate-pulse"></div>
              
              {/* Shield Energy Ring */}
              <div className="absolute inset-0 border-2 border-blue-300/30 rounded-full scale-150"
                   style={{ animation: `shieldRing ${6 + i}s linear infinite` }}></div>
              
              {/* Connection Lines to Adjacent Shields */}
              {i < 7 && (i + 1) % 3 !== 0 && (
                <svg className="absolute left-20 top-10 w-32 h-8" viewBox="0 0 128 32">
                  <path
                    d="M0,16 Q32,8 64,16 T128,16"
                    stroke="rgba(236, 72, 153, 0.4)"
                    strokeWidth="3"
                    fill="none"
                    style={{
                      strokeDasharray: '8,4',
                      animation: `connectionFlow ${5 + i}s linear infinite`,
                      filter: 'drop-shadow(0 0 4px rgba(236, 72, 153, 0.3))'
                    }}
                  />
                  {/* Energy Pulse Along Connection */}
                  <circle r="3" fill="rgba(236, 72, 153, 0.8)">
                    <animateMotion dur={`${4 + i}s`} repeatCount="indefinite">
                      <mpath href="#connectionPath"/>
                    </animateMotion>
                  </circle>
                  <path id="connectionPath" d="M0,16 Q32,8 64,16 T128,16" fill="none" opacity="0"/>
                </svg>
              )}
              
              {/* Vertical Connections */}
              {i < 5 && (
                <svg className="absolute left-10 top-20 w-8 h-24" viewBox="0 0 32 96">
                  <path
                    d="M16,0 Q8,24 16,48 T16,96"
                    stroke="rgba(236, 72, 153, 0.3)"
                    strokeWidth="2"
                    fill="none"
                    style={{
                      strokeDasharray: '6,3',
                      animation: `verticalFlow ${6 + i}s linear infinite`
                    }}
                  />
                </svg>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Protective Aura Layers */}
      <div className="absolute inset-0">
        {/* Outer Protection Ring */}
        <div className="absolute top-1/2 left-1/2 w-[800px] h-[800px] -translate-x-1/2 -translate-y-1/2 border-2 border-blue-400/15 rounded-full"
             style={{ animation: 'protectiveRing 12s linear infinite' }}></div>
        
        {/* Middle Protection Ring */}
        <div className="absolute top-1/2 left-1/2 w-[600px] h-[600px] -translate-x-1/2 -translate-y-1/2 border border-blue-300/20 rounded-full"
             style={{ animation: 'protectiveRing 9s linear infinite reverse' }}></div>
        
        {/* Inner Protection Ring */}
        <div className="absolute top-1/2 left-1/2 w-[400px] h-[400px] -translate-x-1/2 -translate-y-1/2 border border-blue-200/25 rounded-full"
             style={{ animation: 'protectiveRing 6s linear infinite' }}></div>
      </div>

      {/* Mini Shield Satellites */}
      <div className="absolute inset-0">
        {[...Array(12)].map((_, i) => (
          <div
            key={`mini-shield-${i}`}
            className="absolute"
            style={{
              left: `${10 + Math.random() * 80}%`,
              top: `${10 + Math.random() * 80}%`,
              animation: `miniShieldFloat ${8 + Math.random() * 4}s ease-in-out infinite ${Math.random() * 3}s`
            }}
          >
            <Shield className="w-8 h-8 text-blue-300/40" />
            <div className="absolute inset-0 bg-blue-300/10 rounded-full blur-md scale-125 animate-pulse"></div>
          </div>
        ))}
      </div>

      {/* Security Scan Lines */}
      <div className="absolute inset-0">
        {[...Array(4)].map((_, i) => (
          <div
            key={`scan-${i}`}
            className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent"
            style={{
              top: `${25 * i + 10}%`,
              animation: `securityScan ${6 + i * 2}s linear infinite ${i * 1.5}s`
            }}
          ></div>
        ))}
      </div>

      {/* Floating Safety Particles */}
      <div className="absolute inset-0">
        {[...Array(35)].map((_, i) => (
          <div
            key={`safety-particle-${i}`}
            className="absolute w-2 h-2 bg-blue-300/50 rounded-full"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animation: `safetyFloat ${4 + Math.random() * 6}s ease-in-out infinite ${Math.random() * 3}s`
            }}
          ></div>
        ))}
      </div>

      {/* Defensive Barrier Waves */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -inset-20">
          {[...Array(3)].map((_, i) => (
            <div
              key={`barrier-${i}`}
              className="absolute inset-0 border-2 border-blue-400/10 rounded-full"
              style={{
                animation: `barrierWave ${10 + i * 3}s linear infinite ${i * 2}s`
              }}
            ></div>
          ))}
        </div>
      </div>

      {/* Subtle Grid Pattern for Structure */}
      <div className="absolute inset-0 opacity-5">
        <div className="h-full w-full" 
             style={{
               backgroundImage: `radial-gradient(circle at 1px 1px, rgba(236, 72, 153, 0.4) 1px, transparent 0)`,
               backgroundSize: '60px 60px'
             }}></div>
      </div>

      {/* CSS Animations */}
      <style jsx>{`
        @keyframes shieldPulse {
          0%, 100% { 
            transform: scale(1) rotate(0deg); 
            opacity: 0.7; 
            filter: brightness(1);
          }
          50% { 
            transform: scale(1.05) rotate(2deg); 
            opacity: 1; 
            filter: brightness(1.2);
          }
        }
        
        @keyframes shieldRing {
          0% { 
            transform: scale(1.5) rotate(0deg); 
            opacity: 0.2; 
          }
          50% { 
            opacity: 0.4; 
          }
          100% { 
            transform: scale(1.8) rotate(360deg); 
            opacity: 0.1; 
          }
        }
        
        @keyframes connectionFlow {
          0% { 
            stroke-dashoffset: 24; 
            opacity: 0.3; 
          }
          50% { 
            opacity: 0.8; 
          }
          100% { 
            stroke-dashoffset: -24; 
            opacity: 0.3; 
          }
        }
        
        @keyframes verticalFlow {
          0% { 
            stroke-dashoffset: 18; 
            opacity: 0.2; 
          }
          100% { 
            stroke-dashoffset: -18; 
            opacity: 0.2; 
          }
        }
        
        @keyframes protectiveRing {
          0% { 
            transform: translate(-50%, -50%) rotate(0deg) scale(1); 
            opacity: 0.15; 
          }
          50% { 
            opacity: 0.3; 
          }
          100% { 
            transform: translate(-50%, -50%) rotate(360deg) scale(1.02); 
            opacity: 0.15; 
          }
        }
        
        @keyframes miniShieldFloat {
          0%, 100% { 
            transform: translateY(0px) rotate(0deg) scale(1); 
            opacity: 0.4; 
          }
          33% { 
            transform: translateY(-12px) rotate(5deg) scale(1.1); 
            opacity: 0.7; 
          }
          66% { 
            transform: translateY(6px) rotate(-3deg) scale(0.95); 
            opacity: 0.5; 
          }
        }
        
        @keyframes securityScan {
          0% { 
            transform: translateX(-100%); 
            opacity: 0; 
          }
          10% { 
            opacity: 0.6; 
          }
          90% { 
            opacity: 0.6; 
          }
          100% { 
            transform: translateX(100%); 
            opacity: 0; 
          }
        }
        
        @keyframes safetyFloat {
          0%, 100% { 
            transform: translateY(0px) scale(1); 
            opacity: 0.3; 
          }
          25% { 
            transform: translateY(-15px) scale(1.2); 
            opacity: 0.8; 
          }
          50% { 
            transform: translateY(-5px) scale(1.1); 
            opacity: 0.6; 
          }
          75% { 
            transform: translateY(-20px) scale(0.9); 
            opacity: 0.4; 
          }
        }
        
        @keyframes barrierWave {
          0% { 
            transform: scale(0.8); 
            opacity: 0.05; 
          }
          50% { 
            transform: scale(1.2); 
            opacity: 0.15; 
          }
          100% { 
            transform: scale(1.5); 
            opacity: 0; 
          }
        }
      `}</style>
    </div>
  );
};

export default ProtectiveShieldBackground; 