"use client";

import React, { useEffect, useState } from "react";

export const InfiniteMovingCards = ({
  items,
  direction = "left",
  speed = "fast",
  pauseOnHover = true,
  className,
}) => {
  const containerRef = React.useRef(null);
  const scrollerRef = React.useRef(null);

  const [start, setStart] = useState(false);

  useEffect(() => {
    if (containerRef.current && scrollerRef.current) {
      const scrollerContent = Array.from(scrollerRef.current.children);
      scrollerContent.forEach((item) => {
        const duplicatedItem = item.cloneNode(true);
        scrollerRef.current.appendChild(duplicatedItem);
      });

      containerRef.current.style.setProperty(
        "--animation-direction",
        direction === "left" ? "forwards" : "reverse"
      );

      let duration = "40s";
      if (speed === "fast") duration = "20s";
      else if (speed === "slow") duration = "80s";

      containerRef.current.style.setProperty("--animation-duration", duration);

      setStart(true);
    }
  }, []);

  return (
    <div
      ref={containerRef}
      className={`scroller relative z-20 max-w-7xl overflow-hidden [mask-image:linear-gradient(to_right,transparent,white_20%,white_80%,transparent)] ${className}`}
    >
      <ul
        ref={scrollerRef}
        className={`flex w-max min-w-full shrink-0 flex-nowrap gap-8 py-8 ${
          start ? "animate-scroll" : ""
        } ${pauseOnHover ? "hover:[animation-play-state:paused]" : ""}`}
      >
        {items.map((item) => (
          <li
            key={item.name}
            className="relative w-[450px] max-w-full shrink-0 rounded-3xl border-2 border-indigo-400/30 bg-gradient-to-br from-slate-800/60 to-indigo-900/40 backdrop-blur-md px-10 py-10 md:w-[550px] shadow-2xl hover:border-indigo-400/50 transition-all duration-300"
          >
            <blockquote>
              <span className="relative z-20 text-lg leading-[1.8] font-medium text-indigo-100 drop-shadow-md">
                {item.quote}
              </span>
              <div className="relative z-20 mt-8 flex flex-row items-center">
                <span className="flex flex-col gap-2">
                  <span className="text-xl font-bold text-indigo-300 drop-shadow-lg">
                    {item.name}
                  </span>
                  <span className="text-base text-indigo-200/80 font-medium">
                    {item.title}
                  </span>
                </span>
              </div>
            </blockquote>
          </li>
        ))}
      </ul>
    </div>
  );
};
