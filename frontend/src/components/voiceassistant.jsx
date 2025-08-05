import { useEffect } from 'react';

const VoiceAssistant = () => {
  useEffect(() => {
    // Load the ElevenLabs widget script
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/@elevenlabs/convai-widget-embed';
    script.async = true;
    script.type = 'text/javascript';
    document.body.appendChild(script);

    // Add the AI Assistant widget with updated agent ID
    const assistant = document.createElement('elevenlabs-convai');
    assistant.setAttribute('agent-id', 'agent_8101k1mkp2agedsskfb6djxev09e');
    document.body.appendChild(assistant);

    // Cleanup on unmount
    return () => {
      document.body.removeChild(script);
      document.body.removeChild(assistant);
    };
  }, []);

  return null;
};

export default VoiceAssistant;