#pragma once

#include <Arduino.h>
#include <NonBlockingRtttl.h>

/* class abstracts underlying RTTTL library 

    Just a simple implementation to start.  At the moment use same
    melody for message and discovery
    Suggest enum type for different sounds
    - on message
    - on discovery

    TODO
    - make message ring tone configurable

*/

class genericBuzzer
{
    public:
        void begin();  // set up buzzer port
        void play(const char *melody); // Generic play function
        void playForced(const char *melody);  // plays even when quiet (Find Hub ring)
        void ring(uint32_t duration_millis);  // repeat ring_song, even when quiet, for this long (0 = stop)
        bool isRinging() const { return _ringing; }
        const char *ringSong() const { return ring_song; }
        void stop();
        void loop();  // loop driven-nonblocking; call every pass (replays the ring)
        void startup();  // play startup sound
        void shutdown();  // play shutdown sound
        bool isPlaying();  // returns true if a sound is still playing else false
        void quiet(bool buzzer_state);  // enables or disables the buzzer
        bool isQuiet();  // get buzzer state on/off

    private:
        // gemini's picks:
        const char *startup_song = "Startup:d=4,o=5,b=160:16c6,16e6,8g6";
        const char *shutdown_song = "Shutdown:d=4,o=5,b=100:8g5,16e5,16c5";
        // Loud, repeating, distinct from message tones (Find Hub ring, `ring` CLI).
        const char *ring_song = "find:d=8,o=7,b=180:c,e,g,4c8,p,c,e,g,4c8,4p";

        bool _ringing = false;
        unsigned long _ring_until = 0;  // millis() deadline while _ringing

        bool _is_quiet = true;
};
