import React from "react";
import { Timeline } from "./ui/timeline";

const flowSteps = [
  {
    step: "1",
    title: "Take the Voice Survey",
    desc: "Answer 3 core + up to 2 adaptive questions via voice. Omnidim.io adapts to your responses and tone.",
  },
  {
    step: "2",
    title: "Get Matched",
    desc: "AI analyzes your answers and recommends the best roommate and room, with clear explanations.",
  },
  {
    step: "3",
    title: "Move In & Connect",
    desc: "View your matches, accept, and start your new journey. Enjoy a safe, compatible living space!",
  },
];

export default function Flow() {
  const data = flowSteps.map((step) => ({
    title: `Step ${step.step}`,
    content: (
      <div>
        <h3 className="text-lg font-semibold text-blue-100 mb-2">
          {step.title}
        </h3>
        <p className="text-sm text-rose-100 mb-4">
          {step.desc}
        </p>
        {/* Placeholder images to match TimelineDemo's style */}
        <div className="grid grid-cols-2 gap-4">
          <img
            src="https://assets.aceternity.com/templates/startup-1.webp"
            alt="step placeholder 1"
            width={500}
            height={500}
            className="h-20 w-full rounded-lg object-cover shadow-[0_0_24px_rgba(236,_72,_153,_0.2),_0_1px_1px_rgba(0,_0,_0,_0.05),_0_0_0_1px_rgba(236,_72,_153,_0.1),_0_0_4px_rgba(236,_72,_153,_0.15),_0_16px_68px_rgba(236,_72,_153,_0.1),_0_1px_0_rgba(255,_255,_255,_0.1)_inset] md:h-44 lg:h-60"
          />
          <img
            src="https://assets.aceternity.com/templates/startup-2.webp"
            alt="step placeholder 2"
            width={500}
            height={500}
            className="h-20 w-full rounded-lg object-cover shadow-[0_0_24px_rgba(236,_72,_153,_0.2),_0_1px_1px_rgba(0,_0,_0,_0.05),_0_0_0_1px_rgba(236,_72,_153,_0.1),_0_0_4px_rgba(236,_72,_153,_0.15),_0_16px_68px_rgba(236,_72,_153,_0.1),_0_1px_0_rgba(255,_255,_255,_0.1)_inset] md:h-44 lg:h-60"
          />
        </div>
      </div>
    ),
  }));

  return (
    <div className="relative w-full overflow-clip ">
      <Timeline data={data} />
    </div>
  );
}

