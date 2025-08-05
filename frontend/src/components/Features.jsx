import { IconArrowLeft, IconArrowRight } from "@tabler/icons-react";
import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";

// To change images in the Features section:
// Edit the 'features' array in App.jsx. Each object has a 'src' property. Replace the URL with your desired image.
// Example:
// {
//   title: 'Feature Title',
//   desc: 'Feature description',
//   icon: '🎤',
//   src: 'https://your-image-url.com/image.jpg',
// }

const Features = ({ features, autoplay = false, bgClass = "bg-black/40 backdrop-blur-lg" }) => {
  const [active, setActive] = useState(0);

  const handleNext = () => {
    setActive((prev) => (prev + 1) % features.length);
  };

  const handlePrev = () => {
    setActive((prev) => (prev - 1 + features.length) % features.length);
  };

  const isActive = (index) => index === active;

  useEffect(() => {
    if (autoplay) {
      const interval = setInterval(handleNext, 5000);
      return () => clearInterval(interval);
    }
  }, [autoplay]);

  const randomRotateY = () => Math.floor(Math.random() * 21) - 10;

  return (
    <section
      id="features"
      className={`relative py-28 md:py-36 w-full overflow-x-hidden ${bgClass}`}
    >
      <div className="mx-auto max-w-5xl px-2 md:px-8 lg:px-12">
        <h2 className="text-6xl font-extrabold text-center text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-blue-500 mb-20 drop-shadow-[0_2px_8px_rgba(236,72,153,0.7)]">
          Designed for Women, by Women, with Intelligence
        </h2>
        <div className="relative grid grid-cols-1 gap-20 md:grid-cols-2 items-center md:gap-x-32 md:gap-y-20">
          <div>
            <div className="relative h-[420px] w-full md:h-[520px] lg:h-[600px] xl:h-[700px]">
              <AnimatePresence>
                {features.map((feature, index) => (
                  <motion.div
                    key={feature.src}
                    initial={{
                      opacity: 0,
                      scale: 0.9,
                      z: -100,
                      rotate: randomRotateY(),
                    }}
                    animate={{
                      opacity: isActive(index) ? 1 : 0.7,
                      scale: isActive(index) ? 1 : 0.95,
                      z: isActive(index) ? 0 : -100,
                      rotate: isActive(index) ? 0 : randomRotateY(),
                      zIndex: isActive(index) ? 40 : features.length + 2 - index,
                      y: isActive(index) ? [0, -80, 0] : 0,
                    }}
                    exit={{
                      opacity: 0,
                      scale: 0.9,
                      z: 100,
                      rotate: randomRotateY(),
                    }}
                    transition={{
                      duration: 0.4,
                      ease: "easeInOut",
                    }}
                    className="absolute inset-0 origin-bottom"
                    style={{ pointerEvents: isActive(index) ? 'auto' : 'none' }}
                  >
                    <img
                      src={feature.src}
                      alt={feature.title}
                      width={800}
                      height={800}
                      draggable={false}
                      className="h-full w-full rounded-3xl object-cover object-center border-2 border-blue-400/40 shadow-2xl"
                    />
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </div>
          <div className="flex flex-col justify-between py-4">
            <motion.div
              key={active}
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              exit={{ y: -20, opacity: 0 }}
              transition={{ duration: 0.2, ease: "easeInOut" }}
            >
              <div className="text-7xl mb-6 animate-pulse">{features[active].icon}</div>
              <h3 className="text-4xl font-bold text-blue-300 mb-6 drop-shadow-lg">{features[active].title}</h3>
              <motion.p className="mt-8 text-2xl text-blue-100 drop-shadow-md">
                {features[active].desc.split(" ").map((word, index) => (
                  <motion.span
                    key={index}
                    initial={{ filter: "blur(10px)", opacity: 0, y: 5 }}
                    animate={{ filter: "blur(0px)", opacity: 1, y: 0 }}
                    transition={{ duration: 0.2, ease: "easeInOut", delay: 0.02 * index }}
                    className="inline-block"
                  >
                    {word}&nbsp;
                  </motion.span>
                ))}
              </motion.p>
            </motion.div>
            <div className="flex gap-4 pt-20 mt-5 md:pt-0">
              <button
                onClick={handlePrev}
                className="group/button flex h-10 w-10 items-center justify-center rounded-full bg-slate-800/90 hover:bg-slate-700/90"
              >
                <IconArrowLeft className="h-7 w-7 text-blue-400 transition-transform duration-300 group-hover/button:rotate-12" />
              </button>
              <button
                onClick={handleNext}
                className="group/button flex h-10 w-10 items-center justify-center rounded-full bg-slate-800/90 hover:bg-slate-700/90"
              >
                <IconArrowRight className="h-7 w-7 text-blue-400 transition-transform duration-300 group-hover/button:-rotate-12" />
              </button>
            </div>
          </div>
        </div>
        <div
          className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          style={{ animation: "scanLine 6s linear infinite" }}
        ></div>
      </div>
      <style jsx>{`
        @keyframes scanLine {
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
      `}</style>
    </section>
  );
};

export default Features;
