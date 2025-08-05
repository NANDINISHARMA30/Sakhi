import React from 'react';
import { motion } from 'framer-motion';

const heroVariants = {
  hidden: { opacity: 0, y: 40 },
  visible: { opacity: 1, y: 0, transition: { duration: 1 } },
};

const Hero = () => (
  <section className="w-full min-h-screen flex items-center justify-center text-center px-4 sm:px-6 lg:px-8 xl:px-12">
    <motion.div
      variants={heroVariants}
      initial="hidden"
      animate="visible"
      className="w-full max-w-none mx-auto"
    >
      <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-6xl xl:text-7xl font-extrabold text-white mb-6 leading-tight drop-shadow-lg">
        Find Your Perfect Roommate.<br/>
        <span className="text-blue-400">Safe. Compatible. Empowering.</span>
      </h1>
      <p className="text-lg sm:text-xl md:text-xl lg:text-2xl text-blue-100 mb-8 drop-shadow-md max-w-4xl mx-auto">
        sakhi is India's first AI-powered roommate and room matching platform for women—voice-first, bias-free, and built for trust.
      </p>
      <motion.a
        href="#features"
        whileHover={{ scale: 1.05 }}
        className="inline-block bg-blue-600 text-white px-8 sm:px-10 md:px-12 py-3 sm:py-4 md:py-5 rounded-full text-lg sm:text-xl md:text-xl font-semibold shadow-lg hover:bg-blue-700 transition"
      >
        Start Your Journey
      </motion.a>
    </motion.div>
  </section>
);

export default Hero; 