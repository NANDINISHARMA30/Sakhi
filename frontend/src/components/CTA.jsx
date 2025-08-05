import React from 'react';
import { motion } from 'framer-motion';

const CTA = () => (
  <section id="cta" className="py-20 bg-blue-600 text-white text-center">
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.8 }}
      className="max-w-2xl mx-auto"
    >
      <h2 className="text-3xl font-bold mb-4">Ready to Find Your Perfect Roommate?</h2>
      <p className="text-lg mb-8">Join sakhi today and discover a safe, compatible living space tailored to you.</p>
      <a
        href="#"
        className="inline-block bg-white text-blue-600 px-10 py-4 rounded-full text-lg font-semibold hover:bg-gray-100 transition shadow-lg"
      >
        Sign Up Now
      </a>
    </motion.div>
  </section>
);

export default CTA; 