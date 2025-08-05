import React from "react";
import { InfiniteMovingCards } from "./ui/infinite-moving-cards";

const techHighlights = [
  {
    quote: "Conversational, sentiment-aware, and multilingual. Adapts questions based on your responses.",
    name: "Omnidim.io Voice AI",
    title: "Voice Interaction",
  },
  {
    quote: "Python, Pandas, and Scikit-learn power a robust, explainable compatibility algorithm.",
    name: "Matching Engine",
    title: "Compatibility Algorithm",
  },
  {
    quote: "Scalable, secure, and real-time database for user profiles and room assignments.",
    name: "Firebase Firestore",
    title: "Database",
  },
  {
    quote: "Ensures ethical, unbiased, and transparent matching for all users.",
    name: "IBM AI Fairness 360",
    title: "Fairness Framework",
  },
];

const TechnicalArchitecture = () => (
  <section
    className="py-28 bg-gradient-to-br from-slate-900/90 via-blue-900/70 to-blue-900/60 backdrop-blur-lg flex flex-col items-center justify-center relative overflow-hidden border-y border-blue-400/20"
    style={{
      backgroundImage: `radial-gradient(circle at 1px 1px, rgba(139, 92, 246, 0.2) 1px, transparent 0)`,
      backgroundSize: "60px 60px",
    }}
  >
    <h2 className="text-5xl font-bold text-center text-white mb-16 drop-shadow-xl dark:text-gray-100 relative">
      The Intelligence Behind HarmonyMatch
      <span
        className="absolute inset-0 -z-10 bg-blue-400/10 rounded-full blur-2xl"
        style={{ animation: "pulseGlow 6s ease-in-out infinite" }}
      ></span>
    </h2>
    <InfiniteMovingCards
      items={techHighlights}
      direction="right"
      speed="slow"
      pauseOnHover={true}
      className="max-w-7xl"
    />
    <style jsx>{`
      @keyframes pulseGlow {
        0%, 100% {
          opacity: 0.2;
          transform: scale(1);
        }
        50% {
          opacity: 0.4;
          transform: scale(1.05);
        }
      }
      .infinite-moving-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(139, 92, 246, 0.1);
        box-shadow: 0 4px 12px rgba(139, 92, 246, 0.15);
        backdrop-filter: blur(4px);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
      }
      .infinite-moving-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 6px 16px rgba(139, 92, 246, 0.25);
      }
    `}</style>
  </section>
);

export default TechnicalArchitecture;