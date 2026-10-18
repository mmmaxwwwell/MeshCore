#pragma once

// Overlay mesh policy (companion fork, OVERLAY_MESH): what our companions tag
// with the overlay region and what they relay. Shared by the companion
// firmware (examples/companion_radio/MyMesh.cpp) and the host multi-hop
// simulator (test/test_overlay), so the simulator exercises the same rules.
//
// Rules (docs: homelab docs/build-notes/meshcore-trackers-plan.md):
//  * TAG a flood when the overlay is on and it goes to OUR nodes: a DM/ACK/
//    path return/reply to a FAVOURITED contact, or a message on a group
//    channel whose name starts with '~' (the group's overlay channel).
//    Public, #hashtag and other private channels stay untagged, so groups we
//    share with strangers keep working over the public mesh.
//  * RELAY (client repeat on) only overlay-tagged floods, bounded in hops,
//    and direct packets (their paths are learned from overlay floods). Never
//    an untagged public flood: no repeaters, no strangers' traffic.

#include <Packet.h>
#include <helpers/TransportKeyStore.h>

namespace overlay {

constexpr uint8_t MAX_HOPS = 8;
constexpr char CHANNEL_PREFIX = '~';

inline bool isOverlayChannelName(const char* name) {
  return name != nullptr && name[0] == CHANNEL_PREFIX;
}

inline bool tagForContact(bool overlay_on, uint8_t contact_flags) {
  return overlay_on && (contact_flags & 1);
}

inline bool tagForChannel(bool overlay_on, const char* channel_name) {
  return overlay_on && isOverlayChannelName(channel_name);
}

inline bool isOverlayFlood(bool overlay_on, const TransportKey& key, const mesh::Packet* pkt) {
  return overlay_on && pkt->getRouteType() == ROUTE_TYPE_TRANSPORT_FLOOD
      && pkt->transport_codes[0] == key.calcTransportCode(pkt);
}

inline bool allowForward(bool repeat_on, bool overlay_on, const TransportKey& key, const mesh::Packet* pkt) {
  if (!repeat_on) return false;
  if (pkt->isRouteFlood()) return isOverlayFlood(overlay_on, key, pkt) && pkt->getPathHashCount() < MAX_HOPS;
  return true;
}

}  // namespace overlay
