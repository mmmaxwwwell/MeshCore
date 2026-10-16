#include <helpers/BaseChatMesh.h>
#include <Utils.h>

#ifndef SERVER_RESPONSE_DELAY
  #define SERVER_RESPONSE_DELAY   300
#endif

#ifndef TXT_ACK_DELAY
  #define TXT_ACK_DELAY     200
#endif

#define CLI_REPLY_DELAY_MILLIS      600

void BaseChatMesh::sendFloodScoped(const ContactInfo& recipient, mesh::Packet* pkt, uint32_t delay_millis) {
  sendFlood(pkt, delay_millis);
}
void BaseChatMesh::sendFloodScoped(const mesh::GroupChannel& channel, mesh::Packet* pkt, uint32_t delay_millis) {
  sendFlood(pkt, delay_millis);
}

mesh::Packet* BaseChatMesh::createSelfAdvert(const char* name) {
  uint8_t app_data[MAX_ADVERT_DATA_SIZE];
  uint8_t app_data_len;
  {
    AdvertDataBuilder builder(ADV_TYPE_CHAT, name);
    app_data_len = builder.encodeTo(app_data);
  }

  return createAdvert(self_id, app_data, app_data_len);
}

mesh::Packet* BaseChatMesh::createSelfAdvert(const char* name, double lat, double lon) {
  uint8_t app_data[MAX_ADVERT_DATA_SIZE];
  uint8_t app_data_len;
  {
    AdvertDataBuilder builder(ADV_TYPE_CHAT, name, lat, lon);
    app_data_len = builder.encodeTo(app_data);
  }

  return createAdvert(self_id, app_data, app_data_len);
}

void BaseChatMesh::sendAckTo(const ContactInfo& dest, const uint8_t* ack_hash, uint8_t ack_len) {
  if (dest.out_path_len == OUT_PATH_UNKNOWN) {
    mesh::Packet* ack = createAck(ack_hash, ack_len);
    if (ack) sendFloodScoped(dest, ack, TXT_ACK_DELAY);
  } else {
    uint32_t d = TXT_ACK_DELAY;
    if (getExtraAckTransmitCount() > 0) {
      mesh::Packet* a1 = createMultiAck(ack_hash, ack_len, 1);
      if (a1) sendDirect(a1, dest.out_path, dest.out_path_len, d);
      d += 300;
    }

    mesh::Packet* a2 = createAck(ack_hash, ack_len);
    if (a2) sendDirect(a2, dest.out_path, dest.out_path_len, d);
  }
}

void BaseChatMesh::bootstrapRTCfromContacts() {
  uint32_t latest = 0;
  for (int i = 0; i < num_contacts; i++) {
    if (contactLastmod(i) > latest) {
      latest = contactLastmod(i);
    }
  }
  if (latest != 0) {
    getRTCClock()->setCurrentTime(latest + 1);
  }
}

#ifdef CONTACTS_PAGED
ContactInfo* BaseChatMesh::allocateContactSlot(bool transient_only) {
  int oldest_idx = -1;
  uint32_t oldest_lastmod = 0xFFFFFFFF;
  if (transient_only) {
    for (int i = 0; i < MAX_ANON_CONTACTS; i++) {
      if (anon[i].type == ADV_TYPE_NONE && anon[i].lastmod < oldest_lastmod) {
        oldest_lastmod = anon[i].lastmod;
        oldest_idx = i;
      }
    }
    return oldest_idx >= 0 ? &anon[oldest_idx] : NULL;   // NOTE: do NOT call onContactOverwrite()
  }

  int idx = -1;
  if (num_contacts < c_capacity) {
    idx = num_contacts++;
  } else if (shouldOverwriteWhenFull() || c_force_overwrite) {
    for (int i = 0; i < CONTACT_CACHE_SIZE; i++) {
      if (ccache[i].idx >= 0) cacheSyncMeta(ccache[i]);   // index lastmod/flags current before choosing
    }
    for (int i = MAX_ANON_CONTACTS; i < num_contacts; i++) {
      bool is_favourite = (cidx[i].flags & 0x01) != 0;
      if (!is_favourite && cidx[i].lastmod < oldest_lastmod) {
        oldest_lastmod = cidx[i].lastmod;
        oldest_idx = i;
      }
    }
    if (oldest_idx < 0) return NULL;
    ContactInfo* old = contactAt(oldest_idx);
    if (old == NULL) return NULL;
    onContactOverwrite(old->id.pub_key);
    freeRecord(oldest_idx);   // the new contact goes to its own bucket
    if (cidx[oldest_idx].cslot >= 0) ccache[cidx[oldest_idx].cslot].idx = -1;   // drop, no write-back
    idx = oldest_idx;
  } else {
    return NULL;
  }

  memset(&cidx[idx], 0, sizeof(cidx[idx]));
  cidx[idx].slot = 0xFF;
  cidx[idx].cslot = -1;
  int cs = cacheLoad(idx);   // a cache slot without a record: slot == 0xFF
  if (cs < 0) {
    if (idx == num_contacts - 1) num_contacts--;
    return NULL;
  }
  memset(&ccache[cs].c, 0, sizeof(ccache[cs].c));
  c_pending = idx;
  return &ccache[cs].c;
}

// stores the contact allocateContactSlot() handed out, once the caller has filled it in
void BaseChatMesh::commitNewContact() {
  int idx = c_pending;
  c_pending = -1;
  if (idx < MAX_ANON_CONTACTS || idx >= num_contacts || cidx[idx].cslot < 0) return;
  ContactCacheSlot& cs = ccache[cidx[idx].cslot];
  memcpy(cidx[idx].key, cs.c.id.pub_key, 4);

  // first free slot in this bucket's file
  uint8_t used[32];
  memset(used, 0, sizeof(used));
  for (int i = MAX_ANON_CONTACTS; i < num_contacts; i++) {
    if (i != idx && cidx[i].key[0] == cidx[idx].key[0] && cidx[i].slot != 0xFF) {
      used[cidx[i].slot >> 3] |= 1 << (cidx[i].slot & 7);
    }
  }
  int slot = 0;
  while (slot < 255 && (used[slot >> 3] & (1 << (slot & 7)))) slot++;
  if (slot >= 255) {   // bucket full (255 contacts sharing one key byte): drop it
    cs.idx = -1;
    num_contacts--;
    memmove(&cidx[idx], &cidx[idx + 1], (num_contacts - idx) * sizeof(cidx[0]));
    for (int i = 0; i < CONTACT_CACHE_SIZE; i++) if (ccache[i].idx > idx) ccache[i].idx--;
    return;
  }
  cidx[idx].slot = slot;
  cs.crc = 0;          // force the write
  cacheWriteBack(cs);

}
#else
void BaseChatMesh::commitNewContact() { }

ContactInfo* BaseChatMesh::allocateContactSlot(bool transient_only) {
  int oldest_idx = -1;
  uint32_t oldest_lastmod = 0xFFFFFFFF;
  if (transient_only) {
    // only allocate from first N
    for (int i = 0; i < MAX_ANON_CONTACTS; i++) {
      if (contacts[i].type == ADV_TYPE_NONE && contacts[i].lastmod < oldest_lastmod) {
        oldest_lastmod = contacts[i].lastmod;
        oldest_idx = i;
      }
    }
    if (oldest_idx >= 0) {
      // NOTE: do NOT call onContactOverwrite()
      return &contacts[oldest_idx];
    }
  } else {
    if (num_contacts < MAX_ANON_CONTACTS+MAX_CONTACTS) {
      return &contacts[num_contacts++];
    } else if (shouldOverwriteWhenFull()) {
      // Find oldest non-favourite contact by oldest lastmod timestamp
      for (int i = MAX_ANON_CONTACTS; i < num_contacts; i++) {
        bool is_favourite = (contacts[i].flags & 0x01) != 0;
        if (!is_favourite && contacts[i].lastmod < oldest_lastmod) {
          oldest_lastmod = contacts[i].lastmod;
          oldest_idx = i;
        }
      }
      if (oldest_idx >= 0) {
        onContactOverwrite(contacts[oldest_idx].id.pub_key);
        return &contacts[oldest_idx];
      }
    }
  }
  return NULL; // no space, no overwrite or all contacts are all favourites
}
#endif

void BaseChatMesh::populateContactFromAdvert(ContactInfo& ci, const mesh::Identity& id, const AdvertDataParser& parser, uint32_t timestamp) {
  memset(&ci, 0, sizeof(ci));
  ci.id = id;
  ci.out_path_len = OUT_PATH_UNKNOWN;
  StrHelper::strncpy(ci.name, parser.getName(), sizeof(ci.name));
  ci.type = parser.getType();
  if (parser.hasLatLon()) {
    ci.gps_lat = parser.getIntLat();
    ci.gps_lon = parser.getIntLon();
  }
  ci.last_advert_timestamp = timestamp;
  ci.lastmod = getRTCClock()->getCurrentTime();
}

void BaseChatMesh::onAdvertRecv(mesh::Packet* packet, const mesh::Identity& id, uint32_t timestamp, const uint8_t* app_data, size_t app_data_len) {
  AdvertDataParser parser(app_data, app_data_len);
  if (!(parser.isValid() && parser.hasName())) {
    MESH_DEBUG_PRINTLN("onAdvertRecv: invalid app_data, or name is missing: len=%d", app_data_len);
    return;
  }

  ContactInfo* from = NULL;
  int fi = findContactIdx(id.pub_key, PUB_KEY_SIZE);
  if (fi >= 0 && (from = contactAt(fi)) != NULL) {  // is from one of our contacts
    if (timestamp <= from->last_advert_timestamp) {  // check for replay attacks!!
      MESH_DEBUG_PRINTLN("onAdvertRecv: Possible replay attack, name: %s", from->name);
      return;
    }
  }

  // save a copy of raw advert packet (to support "Share..." function)
  int plen;
  {
    uint8_t save = packet->header;
    packet->header &= ~PH_ROUTE_MASK;
    packet->header |= ROUTE_TYPE_FLOOD;   // make sure transport codes are NOT saved
    plen = packet->writeTo(temp_buf);
    packet->header = save;
  }

  if (from && from->type == ADV_TYPE_NONE) {   // already in contacts, but from a temporary ANON_REQ ?
    memset(from, 0, sizeof(*from));  // clear the anon/temp slot
    from = NULL;  // do normal 'add' flow
  }

  bool is_new = false; // true = not in contacts[], false = exists in contacts[]
  if (from == NULL) {
    if (!shouldAutoAddContactType(parser.getType())) {
      ContactInfo ci;
      populateContactFromAdvert(ci, id, parser, timestamp);
      onDiscoveredContact(ci, true, packet->path_len, packet->path);       // let UI know
      return;
    }

    // check hop limit for new contacts (0 = no limit, 1 = direct (0 hops), N = up to N-1 hops)
    uint8_t max_hops = getAutoAddMaxHops();
    if (max_hops > 0 && packet->getPathHashCount() >= max_hops) {
      ContactInfo ci;
      populateContactFromAdvert(ci, id, parser, timestamp);
      onDiscoveredContact(ci, true, packet->path_len, packet->path);       // let UI know
      return;
    }

    from = allocateContactSlot();
    if (from == NULL) {
      ContactInfo ci;
      populateContactFromAdvert(ci, id, parser, timestamp);
      onDiscoveredContact(ci, true, packet->path_len, packet->path);
      onContactsFull();
      MESH_DEBUG_PRINTLN("onAdvertRecv: unable to allocate contact slot for new contact");
      return;
    }
    
    populateContactFromAdvert(*from, id, parser, timestamp);
    from->sync_since = 0;
    from->shared_secret_valid = false;
  }

  // update
  putBlobByKey(id.pub_key, PUB_KEY_SIZE, temp_buf, plen);
  StrHelper::strncpy(from->name, parser.getName(), sizeof(from->name));
  from->type = parser.getType();
  if (parser.hasLatLon()) {
    from->gps_lat = parser.getIntLat();
    from->gps_lon = parser.getIntLon();
  }
  from->last_advert_timestamp = timestamp;
  from->lastmod = getRTCClock()->getCurrentTime();
  commitNewContact();   // paged store: a newly allocated contact gets its storage slot now

  onDiscoveredContact(*from, is_new, packet->path_len, packet->path);       // let UI know
}

int BaseChatMesh::searchPeersByHash(const uint8_t* hash) {
  int n = 0;
  for (int i = 0; i < num_contacts && n < MAX_SEARCH_RESULTS; i++) {
#ifdef CONTACTS_PAGED
    static const uint8_t zero_key[4] = {0, 0, 0, 0};   // an unused anon slot: not a peer
    bool match = i < MAX_ANON_CONTACTS ? (anon[i].id.isHashMatch(hash) && memcmp(anon[i].id.pub_key, zero_key, 4) != 0)
               : (PATH_HASH_SIZE <= 4 && memcmp(cidx[i].key, hash, PATH_HASH_SIZE) == 0);
    if (match) {
#else
    if (contacts[i].id.isHashMatch(hash)) {
#endif
      matching_peer_indexes[n++] = i;  // store the INDEXES of matching contacts (for subsequent 'peer' methods)
    }
  }
  return n;
}

void BaseChatMesh::getPeerSharedSecret(uint8_t* dest_secret, int peer_idx) {
  int i = matching_peer_indexes[peer_idx];
  if (i >= 0 && i < num_contacts) {
#ifdef CONTACTS_PAGED
    if (i >= MAX_ANON_CONTACTS && cidx[i].cslot < 0) {
      // a candidate for a MAC check: don't push the cache around for it
      ContactInfo tmp;
      if (readContact(i, tmp)) memcpy(dest_secret, tmp.getSharedSecret(self_id), PUB_KEY_SIZE);
      else memset(dest_secret, 0, PUB_KEY_SIZE);
      return;
    }
#endif
    memcpy(dest_secret, contactAt(i)->getSharedSecret(self_id), PUB_KEY_SIZE);
  } else {
    MESH_DEBUG_PRINTLN("getPeerSharedSecret: Invalid peer idx: %d", i);
  }
}

void BaseChatMesh::onPeerDataRecv(mesh::Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) {
  int i = matching_peer_indexes[sender_idx];
  if (i < 0 || i >= num_contacts) {
    MESH_DEBUG_PRINTLN("onPeerDataRecv: Invalid sender idx: %d", i);
    return;
  }

  ContactInfo* fromp = contactAt(i);
  if (fromp == NULL) return;
  ContactInfo& from = *fromp;

  if (type == PAYLOAD_TYPE_TXT_MSG && len > 5) {
    uint32_t sender_timestamp;
    memcpy(&sender_timestamp, data, 4);  // timestamp (by sender's RTC clock - which could be wrong)
    uint8_t flags = data[4] >> 2;   // message attempt number, and other flags

    // len can be > original length, but 'text' will be padded with zeroes
    data[len] = 0; // need to make a C string again, with null terminator

    if (flags == TXT_TYPE_PLAIN) {
      from.lastmod = getRTCClock()->getCurrentTime(); // update last heard time
      onMessageRecv(from, packet, sender_timestamp, (const char *) &data[5]);  // let UI know

      int text_len = strlen((char *)&data[5]);
      uint8_t ack_hash[6];    // calc truncated hash of the message timestamp + text + sender pub_key, to prove to sender that we got it
      mesh::Utils::sha256(ack_hash, 4, data, 5 + text_len, from.id.pub_key, PUB_KEY_SIZE);
      // NEW: append (potential) extended attempt byte (to make packethash unique)
      ack_hash[4] = data[5 + text_len + 1];
      getRNG()->random(&ack_hash[5], 1);  // make 6th byte random

      if (packet->isRouteFlood()) {
        // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the ACK
        mesh::Packet* path = createPathReturn(from.id, secret, packet->path, packet->path_len,
                                                PAYLOAD_TYPE_ACK, (uint8_t *) &ack_hash, 6);
        if (path) sendFloodScoped(from, path, TXT_ACK_DELAY);
      } else {
        sendAckTo(from, ack_hash, 6);
      }
    } else if (flags == TXT_TYPE_CLI_DATA) {
      char *text = (char *)&data[5];
      onCommandDataRecv(from, packet, sender_timestamp, text);  // let UI know
      // NOTE: no ack expected for CLI_DATA replies
    } else if (flags == TXT_TYPE_CLI_COMMAND) {
      uint8_t temp[166];
      char *command = (char *)&data[5];
      char *reply = (char *)&temp[5];
      *reply = 0;

      onCLICommandRecv(from, packet, sender_timestamp, command, reply);  // let UI know
      // NOTE: no ack expected for CLI_COMMAND replies

      int text_len = strlen(reply);
      if (text_len > 0) {
        uint32_t timestamp = getRTCClock()->getCurrentTimeUnique();
        if (timestamp == sender_timestamp) {
          // WORKAROUND: the two timestamps need to be different, in the CLI view
          timestamp++;
        }
        memcpy(temp, &timestamp, 4);
        temp[4] = (TXT_TYPE_CLI_DATA << 2);

        auto reply_pkt = createDatagram(PAYLOAD_TYPE_TXT_MSG, from.id, secret, temp, 5 + text_len);
        if (reply_pkt) {
          if (from.out_path_len == OUT_PATH_UNKNOWN) {
            sendFloodScoped(from, reply_pkt, CLI_REPLY_DELAY_MILLIS);
          } else {
            sendDirect(reply_pkt, from.out_path, from.out_path_len, CLI_REPLY_DELAY_MILLIS);
          }
        }
      }
    } else if (flags == TXT_TYPE_SIGNED_PLAIN) {
      if (sender_timestamp > from.sync_since) {  // make sure 'sync_since' is up-to-date
        from.sync_since = sender_timestamp;
      }
      from.lastmod = getRTCClock()->getCurrentTime(); // update last heard time
      onSignedMessageRecv(from, packet, sender_timestamp, &data[5], (const char *) &data[9]);  // let UI know

      uint32_t ack_hash;    // calc truncated hash of the message timestamp + text + OUR pub_key, to prove to sender that we got it
      mesh::Utils::sha256((uint8_t *) &ack_hash, 4, data, 9 + strlen((char *)&data[9]), self_id.pub_key, PUB_KEY_SIZE);

      if (packet->isRouteFlood()) {
        // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the ACK
        mesh::Packet* path = createPathReturn(from.id, secret, packet->path, packet->path_len,
                                                PAYLOAD_TYPE_ACK, (uint8_t *) &ack_hash, 4);
        if (path) sendFloodScoped(from, path, TXT_ACK_DELAY);
      } else {
        sendAckTo(from, (uint8_t *) &ack_hash);
      }
    } else {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: unsupported message type: %u", (uint32_t) flags);
    }
  } else if (type == PAYLOAD_TYPE_REQ && len > 4) {
    uint32_t sender_timestamp;
    memcpy(&sender_timestamp, data, 4);
    uint8_t reply_len = onContactRequest(from, sender_timestamp, &data[4], len - 4, temp_buf);
    if (reply_len > 0) {
      if (packet->isRouteFlood()) {
        // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the response
        mesh::Packet* path = createPathReturn(from.id, secret, packet->path, packet->path_len,
                                              PAYLOAD_TYPE_RESPONSE, temp_buf, reply_len);
        if (path) sendFloodScoped(from, path, SERVER_RESPONSE_DELAY);
      } else {
        mesh::Packet* reply = createDatagram(PAYLOAD_TYPE_RESPONSE, from.id, secret, temp_buf, reply_len);
        if (reply) {
          if (from.out_path_len != OUT_PATH_UNKNOWN) {  // we have an out_path, so send DIRECT
            sendDirect(reply, from.out_path, from.out_path_len, SERVER_RESPONSE_DELAY);
          } else {
            sendFloodScoped(from, reply, SERVER_RESPONSE_DELAY);
          }
        }
      }
    }
  } else if (type == PAYLOAD_TYPE_RESPONSE && len > 0) {
    onContactResponse(from, data, len);
    if (packet->isRouteFlood() && from.out_path_len != OUT_PATH_UNKNOWN) {
      // we have direct path, but other node is still sending flood response, so maybe they didn't receive reciprocal path properly(?)
      handleReturnPathRetry(from, packet->path, packet->path_len);
    }
  }
}

bool BaseChatMesh::onPeerPathRecv(mesh::Packet* packet, int sender_idx, const uint8_t* secret, uint8_t* path, uint8_t path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) {
  int i = matching_peer_indexes[sender_idx];
  if (i < 0 || i >= num_contacts) {
    MESH_DEBUG_PRINTLN("onPeerPathRecv: Invalid sender idx: %d", i);
    return false;
  }

  ContactInfo* fromp = contactAt(i);
  if (fromp == NULL) return false;
  ContactInfo& from = *fromp;

  return onContactPathRecv(from, packet->path, packet->path_len, path, path_len, extra_type, extra, extra_len);
}

bool BaseChatMesh::onContactPathRecv(ContactInfo& from, uint8_t* in_path, uint8_t in_path_len, uint8_t* out_path, uint8_t out_path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) {
  // NOTE: default impl, we just replace the current 'out_path' regardless, whenever sender sends us a new out_path.
  // FUTURE: could store multiple out_paths per contact, and try to find which is the 'best'(?)
  from.out_path_len = mesh::Packet::copyPath(from.out_path, out_path, out_path_len);  // store a copy of path, for sendDirect()
  from.lastmod = getRTCClock()->getCurrentTime();

  onContactPathUpdated(from);

  if (extra_type == PAYLOAD_TYPE_ACK && extra_len >= 4) {
    // also got an encoded ACK!
    if (processAck(extra) != NULL) {
      txt_send_timeout = 0;   // matched one we're waiting for, cancel timeout timer
    }
  } else if (extra_type == PAYLOAD_TYPE_RESPONSE && extra_len > 0) {
    onContactResponse(from, extra, extra_len);
  }
  return true;  // send reciprocal path if necessary
}

void BaseChatMesh::onAckRecv(mesh::Packet* packet, uint32_t ack_crc) {
  ContactInfo* from;
  if ((from = processAck((uint8_t *)&ack_crc)) != NULL) {
    txt_send_timeout = 0;   // matched one we're waiting for, cancel timeout timer
    packet->markDoNotRetransmit();   // ACK was for this node, so don't retransmit

    if (packet->isRouteFlood() && from->out_path_len != OUT_PATH_UNKNOWN) {
      // we have direct path, but other node is still sending flood, so maybe they didn't receive reciprocal path properly(?)
      handleReturnPathRetry(*from, packet->path, packet->path_len);
    }
  }
}

void BaseChatMesh::handleReturnPathRetry(const ContactInfo& contact, const uint8_t* path, uint8_t path_len) {
  // NOTE: simplest impl is just to re-send a reciprocal return path to sender (DIRECTLY)
  //        override this method in various firmwares, if there's a better strategy
  mesh::Packet* rpath = createPathReturn(contact.id, contact.getSharedSecret(self_id), path, path_len, 0, NULL, 0);
  if (rpath) sendDirect(rpath, contact.out_path, contact.out_path_len, 3000);   // 3 second delay
}

#ifdef MAX_GROUP_CHANNELS
int BaseChatMesh::searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel dest[], int max_matches) {
  int n = 0;
  for (int i = 0; i < MAX_GROUP_CHANNELS && n < max_matches; i++) {
    // Skip empty/unconfigured slots. An empty slot has an all-zero secret and
    // therefore matches null-key group traffic (a node transmitting with an
    // unset PSK): the zero-key MAC validates against the empty slot and the
    // foreign message is delivered as if it belonged to that channel. Any node
    // with a free channel slot would otherwise act as a null-key sink.
    if (channels[i].name[0] == 0) continue;
    if (channels[i].channel.hash[0] == hash[0]) {
      dest[n++] = channels[i].channel;
    }
  }
  return n;
}
#endif

void BaseChatMesh::onGroupDataRecv(mesh::Packet* packet, uint8_t type, const mesh::GroupChannel& channel, uint8_t* data, size_t len) {
  if (type == PAYLOAD_TYPE_GRP_TXT) {
    if (len < 5) {
      MESH_DEBUG_PRINTLN("onGroupDataRecv: dropping short group text payload len=%d", (uint32_t)len);
      return;
    }

    uint8_t txt_type = data[4];
    if ((txt_type >> 2) != 0) {
      MESH_DEBUG_PRINTLN("onGroupDataRecv: dropping unsupported group text type=%d", (uint32_t)txt_type);
      return;
    }

    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    // len can be > original length, but 'text' will be padded with zeroes
    data[len] = 0; // need to make a C string again, with null terminator

    // notify UI  of this new message
    onChannelMessageRecv(channel, packet, timestamp, (const char *) &data[5]);  // let UI know
  } else if (type == PAYLOAD_TYPE_GRP_DATA) {
    if (len < 3) {
      MESH_DEBUG_PRINTLN("onGroupDataRecv: dropping short group data payload len=%d", (uint32_t)len);
      return;
    }

    uint16_t data_type = ((uint16_t)data[0]) | (((uint16_t)data[1]) << 8);
    uint8_t data_len = data[2];
    size_t available_len = len - 3;

    if (data_len > available_len) {
      MESH_DEBUG_PRINTLN("onGroupDataRecv: dropping malformed group data type=%d len=%d available=%d",
                         (uint32_t)data_type, (uint32_t)data_len, (uint32_t)available_len);
      return;
    }

    onChannelDataRecv(channel, packet, data_type, &data[3], data_len);
  }
}

mesh::Packet* BaseChatMesh::composeMsgPacket(const ContactInfo& recipient, uint32_t timestamp, uint8_t attempt, const char *text, uint32_t& expected_ack) {
  int text_len = strlen(text);
  if (text_len > MAX_TEXT_LEN) return NULL;
  if (attempt > 3 && text_len > MAX_TEXT_LEN-2) return NULL;

  uint8_t temp[5+MAX_TEXT_LEN+1];
  memcpy(temp, &timestamp, 4);   // mostly an extra blob to help make packet_hash unique
  temp[4] = (attempt & 3);
  memcpy(&temp[5], text, text_len + 1);

  // calc expected ACK reply
  mesh::Utils::sha256((uint8_t *)&expected_ack, 4, temp, 5 + text_len, self_id.pub_key, PUB_KEY_SIZE);

  int len = 5 + text_len;
  if (attempt > 3) {
    temp[len++] = 0;  // null terminator
    temp[len++] = attempt;  // hide attempt number at tail end of payload
  }

  return createDatagram(PAYLOAD_TYPE_TXT_MSG, recipient.id, recipient.getSharedSecret(self_id), temp, len);
}

int  BaseChatMesh::sendMessage(const ContactInfo& recipient, uint32_t timestamp, uint8_t attempt, const char* text, uint32_t& expected_ack, uint32_t& est_timeout) {
  mesh::Packet* pkt = composeMsgPacket(recipient, timestamp, attempt, text, expected_ack);
  if (pkt == NULL) return MSG_SEND_FAILED;

  uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());

  int rc;
  if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
    sendFloodScoped(recipient, pkt);
    txt_send_timeout = futureMillis(est_timeout = calcFloodTimeoutMillisFor(t));
    rc = MSG_SEND_SENT_FLOOD;
  } else {
    sendDirect(pkt, recipient.out_path, recipient.out_path_len);
    txt_send_timeout = futureMillis(est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len));
    rc = MSG_SEND_SENT_DIRECT;
  }
  return rc;
}

int  BaseChatMesh::sendCommandData(const ContactInfo& recipient, uint32_t timestamp, uint8_t attempt, uint8_t txt_type, const char* text, uint32_t& est_timeout) {
  int text_len = strlen(text);
  if (text_len > MAX_TEXT_LEN) return MSG_SEND_FAILED;

  uint8_t temp[5+MAX_TEXT_LEN+1];
  memcpy(temp, &timestamp, 4);   // mostly an extra blob to help make packet_hash unique
  temp[4] = (attempt & 3) | (txt_type << 2);
  memcpy(&temp[5], text, text_len + 1);

  auto pkt = createDatagram(PAYLOAD_TYPE_TXT_MSG, recipient.id, recipient.getSharedSecret(self_id), temp, 5 + text_len);
  if (pkt == NULL) return MSG_SEND_FAILED;

  uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());
  int rc;
  if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
    sendFloodScoped(recipient, pkt);
    txt_send_timeout = futureMillis(est_timeout = calcFloodTimeoutMillisFor(t));
    rc = MSG_SEND_SENT_FLOOD;
  } else {
    sendDirect(pkt, recipient.out_path, recipient.out_path_len);
    txt_send_timeout = futureMillis(est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len));
    rc = MSG_SEND_SENT_DIRECT;
  }
  return rc;
}

bool BaseChatMesh::sendGroupMessage(uint32_t timestamp, mesh::GroupChannel& channel, const char* sender_name, const char* text, int text_len) {
  uint8_t temp[5+MAX_TEXT_LEN+32];
  memcpy(temp, &timestamp, 4);   // mostly an extra blob to help make packet_hash unique
  temp[4] = 0;  // TXT_TYPE_PLAIN

  sprintf((char *) &temp[5], "%s: ", sender_name);  // <sender>: <msg>
  char *ep = strchr((char *) &temp[5], 0);
  int prefix_len = ep - (char *) &temp[5];

  if (text_len + prefix_len > MAX_TEXT_LEN) text_len = MAX_TEXT_LEN - prefix_len;
  memcpy(ep, text, text_len);
  ep[text_len] = 0;  // null terminator

  auto pkt = createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, temp, 5 + prefix_len + text_len);
  if (pkt) {
    sendFloodScoped(channel, pkt);
    return true;
  }
  return false;
}

bool BaseChatMesh::sendGroupData(mesh::GroupChannel& channel, uint8_t* path, uint8_t path_len, uint16_t data_type, const uint8_t* data, int data_len) {
  if (data_len < 0) {
    MESH_DEBUG_PRINTLN("sendGroupData: invalid negative data_len=%d", data_len);
    return false;
  }
  if (data_len > MAX_GROUP_DATA_LENGTH) {
    MESH_DEBUG_PRINTLN("sendGroupData: data_len=%d exceeds max=%d", data_len, MAX_GROUP_DATA_LENGTH);
    return false;
  }

  uint8_t temp[3 + MAX_GROUP_DATA_LENGTH];
  temp[0] = (uint8_t)(data_type & 0xFF);
  temp[1] = (uint8_t)(data_type >> 8);
  temp[2] = (uint8_t)data_len;
  if (data_len > 0) memcpy(&temp[3], data, data_len);

  auto pkt = createGroupDatagram(PAYLOAD_TYPE_GRP_DATA, channel, temp, 3 + data_len);
  if (pkt == NULL) {
    MESH_DEBUG_PRINTLN("sendGroupData: unable to create group datagram, data_len=%d", data_len);
    return false;
  }

  if (path_len == OUT_PATH_UNKNOWN) {
    sendFloodScoped(channel, pkt);
  } else {
    sendDirect(pkt, path, path_len);
  }

  return true;
}

bool BaseChatMesh::shareContactZeroHop(const ContactInfo& contact) {
  int plen = getBlobByKey(contact.id.pub_key, PUB_KEY_SIZE, temp_buf);  // retrieve last raw advert packet
  if (plen == 0) return false;  // not found

  auto packet = obtainNewPacket();
  if (packet == NULL) return false;  // no Packets available

  packet->readFrom(temp_buf, plen);  // restore Packet from 'blob'
  uint16_t codes[2];
  codes[0] = codes[1] = 0;   // { 0, 0 } means 'send this nowhere'
  sendZeroHop(packet, codes);
  return true;  // success
}

uint8_t BaseChatMesh::exportContact(const ContactInfo& contact, uint8_t dest_buf[]) {
  return getBlobByKey(contact.id.pub_key, PUB_KEY_SIZE, dest_buf);  // retrieve last raw advert packet
}

bool BaseChatMesh::importContact(const uint8_t src_buf[], uint8_t len) {
  auto pkt = obtainNewPacket();
  if (pkt) {
    if (pkt->readFrom(src_buf, len) && pkt->getPayloadType() == PAYLOAD_TYPE_ADVERT) {
      pkt->header |= ROUTE_TYPE_FLOOD;   // simulate it being received flood-mode
      getTables()->clear(pkt);  // remove packet hash from table, so we can receive/process it again
      _pendingLoopback = pkt;  // loop-back, as if received over radio
      return true;  // success
    } else {
      releasePacket(pkt);   // undo the obtainNewPacket()
    }
  }
  return false; // error
}

int BaseChatMesh::sendLogin(const ContactInfo& recipient, const char* password, uint32_t& est_timeout) {
  mesh::Packet* pkt;
  {
    int tlen;
    uint8_t temp[24];
    uint32_t now = getRTCClock()->getCurrentTimeUnique();
    memcpy(temp, &now, 4);   // mostly an extra blob to help make packet_hash unique
    if (recipient.type == ADV_TYPE_ROOM) {
      memcpy(&temp[4], &recipient.sync_since, 4);
      int len = strlen(password); if (len > 15) len = 15;  // max 15 chars currently
      memcpy(&temp[8], password, len);
      tlen = 8 + len;
    } else {
      int len = strlen(password); if (len > 15) len = 15;  // max 15 chars currently
      memcpy(&temp[4], password, len);
      tlen = 4 + len;
    }

    pkt = createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, self_id, recipient.id, recipient.getSharedSecret(self_id), temp, tlen);
  }
  if (pkt) {
    uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());
    if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
      sendFloodScoped(recipient, pkt);
      est_timeout = calcFloodTimeoutMillisFor(t);
      return MSG_SEND_SENT_FLOOD;
    } else {
      sendDirect(pkt, recipient.out_path, recipient.out_path_len);
      est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len);
      return MSG_SEND_SENT_DIRECT;
    }
  }
  return MSG_SEND_FAILED;
}

int BaseChatMesh::sendAnonReq(const ContactInfo& recipient, const uint8_t* data, uint8_t len, uint32_t& tag, uint32_t& est_timeout) {
  mesh::Packet* pkt;
  {
    uint8_t temp[MAX_PACKET_PAYLOAD];
    tag = getRTCClock()->getCurrentTimeUnique();
    memcpy(temp, &tag, 4);   // tag to match later (also extra blob to help make packet_hash unique)
    memcpy(&temp[4], data, len);

    pkt = createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, self_id, recipient.id, recipient.getSharedSecret(self_id), temp, 4 + len);
  }
  if (pkt) {
    uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());
    if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
      sendFloodScoped(recipient, pkt);
      est_timeout = calcFloodTimeoutMillisFor(t);
      return MSG_SEND_SENT_FLOOD;
    } else {
      sendDirect(pkt, recipient.out_path, recipient.out_path_len);
      est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len);
      return MSG_SEND_SENT_DIRECT;
    }
  }
  return MSG_SEND_FAILED;
}

int  BaseChatMesh::sendRequest(const ContactInfo& recipient, const uint8_t* req_data, uint8_t data_len, uint32_t& tag, uint32_t& est_timeout) {
  if (data_len > MAX_PACKET_PAYLOAD - 16) return MSG_SEND_FAILED;

  mesh::Packet* pkt;
  {
    uint8_t temp[MAX_PACKET_PAYLOAD];
    tag = getRTCClock()->getCurrentTimeUnique();
    memcpy(temp, &tag, 4);   // mostly an extra blob to help make packet_hash unique
    memcpy(&temp[4], req_data, data_len);

    pkt = createDatagram(PAYLOAD_TYPE_REQ, recipient.id, recipient.getSharedSecret(self_id), temp, 4 + data_len);
  }
  if (pkt) {
    uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());
    if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
      sendFloodScoped(recipient, pkt);
      est_timeout = calcFloodTimeoutMillisFor(t);
      return MSG_SEND_SENT_FLOOD;
    } else {
      sendDirect(pkt, recipient.out_path, recipient.out_path_len);
      est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len);
      return MSG_SEND_SENT_DIRECT;
    }
  }
  return MSG_SEND_FAILED;
}

int  BaseChatMesh::sendRequest(const ContactInfo& recipient, uint8_t req_type, uint32_t& tag, uint32_t& est_timeout) {
  mesh::Packet* pkt;
  {
    uint8_t temp[13];
    tag = getRTCClock()->getCurrentTimeUnique();
    memcpy(temp, &tag, 4);   // mostly an extra blob to help make packet_hash unique
    temp[4] = req_type;
    memset(&temp[5], 0, 4);  // reserved (possibly for 'since' param)
    getRNG()->random(&temp[9], 4);   // random blob to help make packet-hash unique

    pkt = createDatagram(PAYLOAD_TYPE_REQ, recipient.id, recipient.getSharedSecret(self_id), temp, sizeof(temp));
  }
  if (pkt) {
    uint32_t t = _radio->getEstAirtimeFor(pkt->getRawLength());
    if (recipient.out_path_len == OUT_PATH_UNKNOWN) {
      sendFloodScoped(recipient, pkt);
      est_timeout = calcFloodTimeoutMillisFor(t);
      return MSG_SEND_SENT_FLOOD;
    } else {
      sendDirect(pkt, recipient.out_path, recipient.out_path_len);
      est_timeout = calcDirectTimeoutMillisFor(t, recipient.out_path_len);
      return MSG_SEND_SENT_DIRECT;
    }
  }
  return MSG_SEND_FAILED;
}

bool BaseChatMesh::startConnection(const ContactInfo& contact, uint16_t keep_alive_secs) {
  int use_idx = -1;
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].keep_alive_millis == 0) {  // free slot?
      use_idx = i;
    } else if (connections[i].server_id.matches(contact.id)) {  // already in table?
      use_idx = i;
      break;
    }
  }
  if (use_idx < 0) {
    return false;   // table is full
  }
  connections[use_idx].server_id = contact.id;
  uint32_t interval = connections[use_idx].keep_alive_millis = ((uint32_t)keep_alive_secs)*1000;
  connections[use_idx].next_ping = futureMillis(interval);
  connections[use_idx].expected_ack = 0;
  connections[use_idx].last_activity = getRTCClock()->getCurrentTime();
  return true;  // success
}

void BaseChatMesh::stopConnection(const uint8_t* pub_key) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].server_id.matches(pub_key)) {
      connections[i].keep_alive_millis = 0;  // mark slot as now free
      connections[i].next_ping = 0;
      connections[i].expected_ack = 0;
      connections[i].last_activity = 0;
      break;
    }
  }
}

bool BaseChatMesh::hasConnectionTo(const uint8_t* pub_key) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].keep_alive_millis > 0 && connections[i].server_id.matches(pub_key)) return true;
  }
  return false;
}

void BaseChatMesh::markConnectionActive(const ContactInfo& contact) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].keep_alive_millis > 0 && connections[i].server_id.matches(contact.id)) {
      connections[i].last_activity = getRTCClock()->getCurrentTime();

      // re-schedule next KEEP_ALIVE, now that we have heard from server
      connections[i].next_ping = futureMillis(connections[i].keep_alive_millis);
      break;
    }
  }
}

ContactInfo* BaseChatMesh::checkConnectionsAck(const uint8_t* data) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].keep_alive_millis > 0 && memcmp(&connections[i].expected_ack, data, 4) == 0) {
      // yes, got an ack for our keep_alive request!
      connections[i].expected_ack = 0;
      connections[i].last_activity = getRTCClock()->getCurrentTime();

      // re-schedule next KEEP_ALIVE, now that we have heard from server
      connections[i].next_ping = futureMillis(connections[i].keep_alive_millis);

      auto id = &connections[i].server_id;
      return lookupContactByPubKey(id->pub_key, PUB_KEY_SIZE);  // yes, a match
    }
  }
  return NULL;  /// no match
}

void BaseChatMesh::checkConnections() {
  // scan connections[] table, send KEEP_ALIVE requests
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    if (connections[i].keep_alive_millis == 0) continue;  // unused slot

    uint32_t now = getRTCClock()->getCurrentTime();
    uint32_t expire_secs = (connections[i].keep_alive_millis / 1000) * 5 / 2;   // 2.5 x keep_alive interval
    if (now >= connections[i].last_activity + expire_secs) {
      // connection now lost
      connections[i].keep_alive_millis = 0;
      connections[i].next_ping = 0;
      connections[i].expected_ack = 0;
      connections[i].last_activity = 0;
      continue;
    }

    if (millisHasNowPassed(connections[i].next_ping)) {
      auto contact = lookupContactByPubKey(connections[i].server_id.pub_key, PUB_KEY_SIZE);
      if (contact == NULL) {
        MESH_DEBUG_PRINTLN("checkConnections(): Keep_alive contact not found!");
        continue;
      }
      if (contact->out_path_len == OUT_PATH_UNKNOWN) {
        MESH_DEBUG_PRINTLN("checkConnections(): Keep_alive contact, no out_path!");
        continue;
      }

      // send KEEP_ALIVE request
      uint8_t data[9];
      uint32_t now = getRTCClock()->getCurrentTimeUnique();
      memcpy(data, &now, 4);
      data[4] = REQ_TYPE_KEEP_ALIVE;
      memcpy(&data[5], &contact->sync_since, 4);
    
      // calc expected ACK reply
      mesh::Utils::sha256((uint8_t *)&connections[i].expected_ack, 4, data, 9, self_id.pub_key, PUB_KEY_SIZE);

      auto pkt = createDatagram(PAYLOAD_TYPE_REQ, contact->id, contact->getSharedSecret(self_id), data, 9);
      if (pkt) {
        sendDirect(pkt, contact->out_path, contact->out_path_len);
      }
    
      // schedule next KEEP_ALIVE
      connections[i].next_ping = futureMillis(connections[i].keep_alive_millis);
    }
  }
}

void BaseChatMesh::resetPathTo(ContactInfo& recipient) {
  recipient.out_path_len = OUT_PATH_UNKNOWN;
}

#ifdef CONTACTS_PAGED
void BaseChatMesh::scanRecentContacts(int last_n, ContactVisitor* visitor) {
  // no sort array in the paged store: select newest-first by the index lastmod
  if (last_n == 0 || last_n > num_contacts) last_n = num_contacts;
  uint32_t below = 0xFFFFFFFF;
  int below_idx = num_contacts;
  ContactInfo c;
  for (int n = 0; n < last_n; n++) {
    int best = -1;
    for (int i = 0; i < num_contacts; i++) {
      uint32_t t = contactLastmod(i);
      bool under = t < below || (t == below && i > below_idx);
      if (under && (best < 0 || t > contactLastmod(best))) best = i;
    }
    if (best < 0) break;
    below = contactLastmod(best);
    below_idx = best;
    if (readContact(best, c)) visitor->onContactVisit(c);
  }
}

ContactInfo* BaseChatMesh::searchContactsByPrefix(const char* name_prefix) {
  int len = strlen(name_prefix);
  ContactInfo c;
  for (int i = 0; i < num_contacts; i++) {
    if (readContact(i, c) && memcmp(c.name, name_prefix, len) == 0) return contactAt(i);
  }
  return NULL;  // not found
}

int BaseChatMesh::findContactIdx(const uint8_t* pub_key, int prefix_len) {
  for (int i = 0; i < MAX_ANON_CONTACTS; i++) {
    if (memcmp(anon[i].id.pub_key, pub_key, prefix_len) == 0) return i;
  }
  int klen = prefix_len < 4 ? prefix_len : 4;
  ContactInfo c;
  for (int i = MAX_ANON_CONTACTS; i < num_contacts; i++) {
    if (memcmp(cidx[i].key, pub_key, klen) != 0) continue;
    if (prefix_len <= 4) return i;
    if (cidx[i].cslot >= 0) {
      if (memcmp(ccache[cidx[i].cslot].c.id.pub_key, pub_key, prefix_len) == 0) return i;
    } else if (readContact(i, c) && memcmp(c.id.pub_key, pub_key, prefix_len) == 0) {
      return i;
    }
  }
  return -1;
}

ContactInfo* BaseChatMesh::lookupContactByPubKey(const uint8_t* pub_key, int prefix_len) {
  int i = findContactIdx(pub_key, prefix_len);
  return i >= 0 ? contactAt(i) : NULL;
}

bool BaseChatMesh::addContact(const ContactInfo& contact) {
  ContactInfo* dest = allocateContactSlot(contact.type == ADV_TYPE_NONE);
  if (dest) {
    *dest = contact;
    dest->shared_secret_valid = false; // mark shared_secret as needing calculation
    if (contact.type != ADV_TYPE_NONE) commitNewContact();
    return true;  // success
  }
  return false;
}

bool BaseChatMesh::removeContact(ContactInfo& contact) {
  int idx = findContactIdx(contact.id.pub_key, PUB_KEY_SIZE);
  if (idx < 0) return false;   // not found
  if (idx < MAX_ANON_CONTACTS) {
    memset(&anon[idx], 0, sizeof(anon[idx]));
    return true;
  }
  freeRecord(idx);
  if (cidx[idx].cslot >= 0) ccache[cidx[idx].cslot].idx = -1;   // drop, no write-back
  num_contacts--;
  memmove(&cidx[idx], &cidx[idx + 1], (num_contacts - idx) * sizeof(cidx[0]));
  for (int i = 0; i < CONTACT_CACHE_SIZE; i++) {
    if (ccache[i].idx > idx) ccache[i].idx--;
  }
  return true;  // Success
}

// ---- paged store internals ----

static uint32_t recCrc(const uint8_t* rec) {   // FNV-1a: only detects change
  uint32_t h = 2166136261u;
  for (int i = 0; i < CONTACT_REC_SIZE; i++) { h ^= rec[i]; h *= 16777619u; }
  return h;
}

void BaseChatMesh::resetContacts() {
  memset(anon, 0, sizeof(anon));
  memset(cidx, 0, sizeof(cidx[0]) * MAX_ANON_CONTACTS);
  for (int i = 0; i < CONTACT_CACHE_SIZE; i++) ccache[i].idx = -1;
  c_tick = c_epoch = 0;
  c_pending = -1;
  c_capacity = MAX_ANON_CONTACTS+MAX_CONTACTS;
  c_force_overwrite = false;
  num_contacts = MAX_ANON_CONTACTS;
}

void BaseChatMesh::onIndexRec(void* ctx, uint8_t slot, const uint8_t* rec) {
  BaseChatMesh* self = (BaseChatMesh *) ctx;
  if (rec[64] == ADV_TYPE_NONE) return;   // free slot
  if (self->num_contacts >= self->c_capacity) return;   // over capacity: never overwrite at load
  ContactIndexEntry& e = self->cidx[self->num_contacts++];
  memcpy(e.key, rec, 4);
  e.type = rec[64];
  e.flags = rec[65];
  memcpy(&e.lastmod, &rec[140], 4);
  e.slot = slot;
  e.cslot = -1;
}

void BaseChatMesh::loadContactIndex() {
  if (_cstore == NULL) return;
  for (int b = 0; b < 256; b++) _cstore->scanBucket(b, onIndexRec, this);
}

uint32_t BaseChatMesh::contactLastmod(int idx) const {
  if (idx < MAX_ANON_CONTACTS) return anon[idx].lastmod;
  if (cidx[idx].cslot >= 0) return ccache[cidx[idx].cslot].c.lastmod;
  return cidx[idx].lastmod;
}

bool BaseChatMesh::readContact(int idx, ContactInfo& dest) const {
  if (idx < 0 || idx >= num_contacts) return false;
  if (idx < MAX_ANON_CONTACTS) { dest = anon[idx]; return true; }
  if (cidx[idx].cslot >= 0) { dest = ccache[cidx[idx].cslot].c; return true; }
  uint8_t rec[CONTACT_REC_SIZE];
  if (_cstore == NULL || cidx[idx].slot == 0xFF
      || !_cstore->readContactRec(cidx[idx].key[0], cidx[idx].slot, rec)) return false;
  dest.readRecord(rec);
  return true;
}

ContactInfo* BaseChatMesh::contactAt(int idx) {
  if (idx < 0 || idx >= num_contacts) return NULL;
  if (idx < MAX_ANON_CONTACTS) return &anon[idx];
  int cs = cidx[idx].cslot >= 0 ? cidx[idx].cslot : cacheLoad(idx);
  if (cs < 0) return NULL;
  ccache[cs].used = ++c_tick;
  ccache[cs].epoch = c_epoch;
  return &ccache[cs].c;
}

void BaseChatMesh::cacheSyncMeta(ContactCacheSlot& cs) {
  ContactIndexEntry& e = cidx[cs.idx];
  e.lastmod = cs.c.lastmod;
  e.type = cs.c.type;
  e.flags = cs.c.flags;
}

void BaseChatMesh::cacheWriteBack(ContactCacheSlot& cs) {
  if (cs.idx < 0) return;
  cacheSyncMeta(cs);
  ContactIndexEntry& e = cidx[cs.idx];
  if (e.slot == 0xFF || _cstore == NULL) return;   // not committed yet
  uint8_t rec[CONTACT_REC_SIZE];
  cs.c.writeRecord(rec);
  uint32_t crc = recCrc(rec);
  if (crc != cs.crc && _cstore->writeContactRec(e.key[0], e.slot, rec)) cs.crc = crc;
}

// loads index entry idx into a cache slot (evicting the least recently used); -1 on failure
int BaseChatMesh::cacheLoad(int idx) {
  int victim = -1;
  for (int i = 0; i < CONTACT_CACHE_SIZE; i++) {
    if (ccache[i].idx < 0) { victim = i; break; }
  }
  if (victim < 0) {
    // LRU, but never one used in this loop() pass: callers may still hold its pointer
    for (int pass = 0; pass < 2 && victim < 0; pass++) {
      uint32_t oldest = 0xFFFFFFFF;
      for (int i = 0; i < CONTACT_CACHE_SIZE; i++) {
        if (pass == 0 && ccache[i].epoch == c_epoch) continue;
        if (ccache[i].used < oldest) { oldest = ccache[i].used; victim = i; }
      }
    }
    if (victim < 0) return -1;
    cacheWriteBack(ccache[victim]);
    cidx[ccache[victim].idx].cslot = -1;
  }
  ContactCacheSlot& cs = ccache[victim];
  cs.crc = 0;
  if (cidx[idx].slot != 0xFF) {
    uint8_t rec[CONTACT_REC_SIZE];
    if (_cstore == NULL || !_cstore->readContactRec(cidx[idx].key[0], cidx[idx].slot, rec)) {
      cs.idx = -1;
      return -1;
    }
    cs.c.readRecord(rec);
    cs.crc = recCrc(rec);
  }
  cs.idx = idx;
  cs.used = ++c_tick;
  cs.epoch = c_epoch;
  cidx[idx].cslot = victim;
  return victim;
}

// clears the contact's storage record (its slot becomes free)
void BaseChatMesh::freeRecord(int idx) {
  ContactIndexEntry& e = cidx[idx];
  if (e.slot != 0xFF && _cstore) {
    uint8_t rec[CONTACT_REC_SIZE];
    memset(rec, 0, sizeof(rec));
    _cstore->writeContactRec(e.key[0], e.slot, rec);
  }
  e.slot = 0xFF;
  if (e.cslot >= 0) ccache[e.cslot].crc = 0;
}

#ifdef CONTACTS_SELFTEST
#ifdef QSPI_POWERSAVE
  #include <helpers/nrf52/QSPIPowerSave.h>
#endif
// Randomised check of the paged store against a plain model, on the real storage.
// Model holds key, name tag and lastmod per live contact.
#define ST_MAX 700
struct StModel { uint8_t key[32]; uint32_t tag; uint32_t lastmod; bool live; };
static StModel st_m[ST_MAX];
static uint32_t st_rng = 0x1234567;
const char* st_summary = "";
static uint32_t stRand() { st_rng ^= st_rng << 13; st_rng ^= st_rng >> 17; st_rng ^= st_rng << 5; return st_rng; }

bool BaseChatMesh::contactStoreSelfTest(ContactPageStore* store, Print& out) {
  ContactPageStore* saved = _cstore;
  _cstore = store;
  resetContacts();
  memset(st_m, 0, sizeof(st_m));
  int live = 0, errors = 0, ops = 0;
  uint32_t t0 = millis(), max_op = 0;

  static char st_log[2048]; st_log[0] = 0;
  #define ST_FAIL(...) do { errors++; int L = strlen(st_log); \
    if (L < (int)sizeof(st_log) - 120) { L += snprintf(st_log + L, sizeof(st_log) - L, "ST FAIL op%d: ", ops); \
      L += snprintf(st_log + L, sizeof(st_log) - L, __VA_ARGS__); snprintf(st_log + L, sizeof(st_log) - L, "\n"); } } while (0)

  auto check_one = [&](int m) {
    ContactInfo* c = lookupContactByPubKey(st_m[m].key, PUB_KEY_SIZE);
    if (!c) { ST_FAIL("missing m=%d", m); return; }
    uint32_t tag; memcpy(&tag, c->name, 4);
    if (tag != st_m[m].tag || c->lastmod != st_m[m].lastmod || c->type != ADV_TYPE_CHAT)
      ST_FAIL("mismatch m=%d tag %lu/%lu lm %lu/%lu", m, (unsigned long)tag, (unsigned long)st_m[m].tag,
              (unsigned long)c->lastmod, (unsigned long)st_m[m].lastmod);
  };
  auto check_all = [&](const char* when) {
    int n = 0;
    ContactsIterator it = startContactsIterator();
    ContactInfo c;
    while (it.hasNext(this, c)) {
      n++;
      int found = -1;
      for (int m = 0; m < ST_MAX; m++) if (st_m[m].live && memcmp(st_m[m].key, c.id.pub_key, 32) == 0) { found = m; break; }
      if (found < 0) { ST_FAIL("%s: unexpected contact %02x%02x", when, c.id.pub_key[0], c.id.pub_key[1]); continue; }
      uint32_t tag; memcpy(&tag, c.name, 4);
      if (tag != st_m[found].tag || c.lastmod != st_m[found].lastmod) ST_FAIL("%s: stale m=%d", when, found);
    }
    if (n != live || getNumContacts() != live) ST_FAIL("%s: count iter=%d table=%d model=%d", when, n, getNumContacts(), live);
    if (strcmp(when, "reboot") != 0) {   // keep the summary short: only final/overwrite checkpoints
      int L = strlen(st_log);
      snprintf(st_log + L, sizeof(st_log) - L, "ST %s errors=%d live=%d ops=%d\n", when, errors, live, ops);
    }
  };
  auto reboot = [&]() {
    flushContacts();
    resetContacts();
    loadContactIndex();
  };
  auto new_key = [&](uint8_t* k) {
    for (int i = 0; i < 32; i++) k[i] = stRand();
    if (stRand() % 4) k[0] = stRand() % 6;   // pile most into 6 buckets: big buckets, slot reuse
  };

  static const char* tname[] = {"add", "modify", "remove", "lookup", "reboot", "idle"};
  uint32_t tmax[6] = {0}, tsum[6] = {0}, tcnt[6] = {0};
  for (int round = 0; round < 2200; round++, ops++) {
    c_epoch++;   // as loop() does
    uint32_t r = stRand() % 100;
    int ty = r < 40 ? 0 : r < 70 ? 1 : r < 82 ? 2 : r < 95 ? 3 : r < 97 ? 4 : 5;
    uint32_t ts = millis();
    if (r < 40 && live < ST_MAX - 10) {                 // add
      int m = 0; while (st_m[m].live) m++;
      new_key(st_m[m].key);
      ContactInfo c; memset(&c, 0, sizeof(c));
      c.id = mesh::Identity(st_m[m].key);
      c.type = ADV_TYPE_CHAT;
      st_m[m].tag = stRand(); memcpy(c.name, &st_m[m].tag, 4);
      st_m[m].lastmod = c.lastmod = 1000000 + ops;
      c.out_path_len = OUT_PATH_UNKNOWN;
      if (!addContact(c)) { ST_FAIL("add failed live=%d", live); continue; }
      st_m[m].live = true; live++;
    } else if (r < 70 && live) {                        // modify (as path/advert updates do)
      int m; do m = stRand() % ST_MAX; while (!st_m[m].live);
      ContactInfo* c = lookupContactByPubKey(st_m[m].key, PUB_KEY_SIZE);
      if (!c) { ST_FAIL("modify: missing"); continue; }
      st_m[m].tag = stRand(); memcpy(c->name, &st_m[m].tag, 4);
      st_m[m].lastmod = c->lastmod = 2000000 + ops;
      if (stRand() % 3 == 0) flushContacts();
    } else if (r < 82 && live) {                        // remove
      int m; do m = stRand() % ST_MAX; while (!st_m[m].live);
      ContactInfo* c = lookupContactByPubKey(st_m[m].key, PUB_KEY_SIZE);
      if (!c || !removeContact(*c)) { ST_FAIL("remove failed"); continue; }
      st_m[m].live = false; live--;
    } else if (r < 95 && live) {                        // lookups + hash search
      int m; do m = stRand() % ST_MAX; while (!st_m[m].live);
      check_one(m);
      int expect = 0;
      for (int k = 0; k < ST_MAX; k++) if (st_m[k].live && st_m[k].key[0] == st_m[m].key[0]) expect++;
      int got = searchPeersByHash(st_m[m].key);
      if (got != (expect < MAX_SEARCH_RESULTS ? expect : MAX_SEARCH_RESULTS)) ST_FAIL("hash search %d/%d", got, expect);
      uint8_t absent[32]; new_key(absent); absent[1] ^= 0x5a;
      if (lookupContactByPubKey(absent, PUB_KEY_SIZE)) ST_FAIL("found absent key");
    } else if (r < 97) {
      reboot();
      check_all("reboot");
    }
    uint32_t dt = millis() - ts;
    if (dt > max_op) max_op = dt;
    if (dt > tmax[ty]) tmax[ty] = dt;
    tsum[ty] += dt; tcnt[ty]++;
    static uint32_t win_max = 0;
    if (dt > win_max) win_max = dt;
    if (ops % 50 == 0) {
      out.printf("ST progress ops=%d live=%d errors=%d elapsed=%lus window_max=%lums\n", ops, live, errors,
                 (unsigned long)((millis() - t0) / 1000), (unsigned long)win_max);
      win_max = 0;
      Serial.flush();
    }
#ifdef QSPI_POWERSAVE
    if (ops % 7 == 0) { delay(QSPI_IDLE_MS + 5); QSPIPowerSave::loop(); }   // real sleep/wake cycles
#endif
#ifdef NRF52_PLATFORM
    NRF_WDT->RR[0] = WDT_RR_RR_Reload;
#endif
    if (errors > 20) break;
  }
  reboot();
  check_all("final");

  // overwrite-oldest when full: capacity = current size, add 5 more
  c_capacity = num_contacts;
  c_force_overwrite = true;
  for (int i = 0; i < 5 && errors <= 20; i++, ops++) {
    c_epoch++;
    int oldest = -1;
    for (int m = 0; m < ST_MAX; m++) if (st_m[m].live && (oldest < 0 || st_m[m].lastmod < st_m[oldest].lastmod)) oldest = m;
    int m = 0; while (st_m[m].live) m++;
    new_key(st_m[m].key);
    ContactInfo c; memset(&c, 0, sizeof(c));
    c.id = mesh::Identity(st_m[m].key); c.type = ADV_TYPE_CHAT;
    st_m[m].tag = stRand(); memcpy(c.name, &st_m[m].tag, 4);
    st_m[m].lastmod = c.lastmod = 3000000 + ops;
    if (!addContact(c)) { ST_FAIL("overwrite add failed"); continue; }
    st_m[m].live = true;
    st_m[oldest].live = false;   // live count unchanged
  }
  reboot();
  check_all("overwrite");

  { int L = strlen(st_log);
    snprintf(st_log + L, sizeof(st_log) - L, "ST DONE errors=%d ops=%d live=%d secs=%lu max_op_ms=%lu\n", errors, ops, live,
             (unsigned long)((millis() - t0) / 1000), (unsigned long)max_op); }
#ifdef QSPI_POWERSAVE
  { int L = strlen(st_log);
    snprintf(st_log + L, sizeof(st_log) - L, "ST qspi sleeps=%lu\n", (unsigned long)QSPIPowerSave::sleeps()); }
#endif
  for (int k = 0; k < 6; k++) {
    int L = strlen(st_log);
    snprintf(st_log + L, sizeof(st_log) - L, "ST time %s n=%lu avg=%lums max=%lums\n", tname[k], (unsigned long)tcnt[k],
             (unsigned long)(tcnt[k] ? tsum[k] / tcnt[k] : 0), (unsigned long)tmax[k]);
  }
  st_summary = st_log;
  resetContacts();
  _cstore = saved;
  return errors == 0;
}
#endif

void BaseChatMesh::flushContacts() {
  for (int i = 0; i < CONTACT_CACHE_SIZE; i++) {
    if (ccache[i].idx >= 0) cacheWriteBack(ccache[i]);
  }
}

#else
static ContactInfo* table;  // pass via global :-(

static int cmp_adv_timestamp(const void *a, const void *b) {
  int a_idx = *((int *)a);
  int b_idx = *((int *)b);
  if (table[b_idx].last_advert_timestamp > table[a_idx].last_advert_timestamp) return 1;
  if (table[b_idx].last_advert_timestamp < table[a_idx].last_advert_timestamp) return -1;
  return 0;
}

void BaseChatMesh::scanRecentContacts(int last_n, ContactVisitor* visitor) {
  for (int i = 0; i < num_contacts; i++) {  // sort the INDEXES into contacts[]
    sort_array[i] = i;
  }
  table = contacts; // pass via global *sigh* :-(
  qsort(sort_array, num_contacts, sizeof(sort_array[0]), cmp_adv_timestamp);

  if (last_n == 0) {
    last_n = num_contacts;   // scan ALL
  } else {
    if (last_n > num_contacts) last_n = num_contacts;
  }
  for (int i = 0; i < last_n; i++) {
    visitor->onContactVisit(contacts[sort_array[i]]);
  }
}

ContactInfo* BaseChatMesh::searchContactsByPrefix(const char* name_prefix) {
  int len = strlen(name_prefix);
  for (int i = 0; i < num_contacts; i++) {
    auto c = &contacts[i];
    if (memcmp(c->name, name_prefix, len) == 0) return c;
  }
  return NULL;  // not found
}

int BaseChatMesh::findContactIdx(const uint8_t* pub_key, int prefix_len) {
  for (int i = 0; i < num_contacts; i++) {
    if (memcmp(contacts[i].id.pub_key, pub_key, prefix_len) == 0) return i;
  }
  return -1;
}

ContactInfo* BaseChatMesh::lookupContactByPubKey(const uint8_t* pub_key, int prefix_len) {
  for (int i = 0; i < num_contacts; i++) {
    auto c = &contacts[i];
    if (memcmp(c->id.pub_key, pub_key, prefix_len) == 0) return c;
  }
  return NULL;  // not found
}

bool BaseChatMesh::addContact(const ContactInfo& contact) {
  ContactInfo* dest = allocateContactSlot(contact.type == ADV_TYPE_NONE);
  if (dest) {
    *dest = contact;
    dest->shared_secret_valid = false; // mark shared_secret as needing calculation
    return true;  // success
  }
  return false;
}

bool BaseChatMesh::removeContact(ContactInfo& contact) {
  int idx = 0;
  while (idx < num_contacts && !contacts[idx].id.matches(contact.id)) {
    idx++;
  }
  if (idx >= num_contacts) return false;   // not found

  // remove from contacts array
  num_contacts--;
  while (idx < num_contacts) {
    contacts[idx] = contacts[idx + 1];
    idx++;
  }
  return true;  // Success
}

#endif

#ifdef MAX_GROUP_CHANNELS
#include <base64.hpp>

ChannelDetails* BaseChatMesh::addChannel(const char* name, const char* psk_base64) {
  if (num_channels < MAX_GROUP_CHANNELS) {
    auto dest = &channels[num_channels];

    memset(dest->channel.secret, 0, sizeof(dest->channel.secret));
    int len = decode_base64((unsigned char *) psk_base64, strlen(psk_base64), dest->channel.secret);
    if (len == 32 || len == 16) {
      mesh::Utils::sha256(dest->channel.hash, sizeof(dest->channel.hash), dest->channel.secret, len);
      StrHelper::strncpy(dest->name, name, sizeof(dest->name));
      num_channels++;
      return dest;
    }
  }
  return NULL;
}
bool BaseChatMesh::getChannel(int idx, ChannelDetails& dest) {
  if (idx >= 0 && idx < MAX_GROUP_CHANNELS) {
    dest = channels[idx];
    return true;
  }
  return false;
}
bool BaseChatMesh::setChannel(int idx, const ChannelDetails& src) {
  static uint8_t zeroes[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

  if (idx >= 0 && idx < MAX_GROUP_CHANNELS) {
    channels[idx] = src;
    if (memcmp(&src.channel.secret[16], zeroes, 16) == 0) {
      mesh::Utils::sha256(channels[idx].channel.hash, sizeof(channels[idx].channel.hash), src.channel.secret, 16);  // 128-bit key
    } else {
      mesh::Utils::sha256(channels[idx].channel.hash, sizeof(channels[idx].channel.hash), src.channel.secret, 32);  // 256-bit key
    }
    return true;
  }
  return false;
}
int BaseChatMesh::findChannelIdx(const mesh::GroupChannel& ch) {
  for (int i = 0; i < MAX_GROUP_CHANNELS; i++) {
    if (memcmp(ch.secret, channels[i].channel.secret, sizeof(ch.secret)) == 0) return i;
  }
  return -1;  // not found
}
#else
ChannelDetails* BaseChatMesh::addChannel(const char* name, const char* psk_base64) {
  return NULL;  // not supported
}
bool BaseChatMesh::getChannel(int idx, ChannelDetails& dest) {
  return false;
}
bool BaseChatMesh::setChannel(int idx, const ChannelDetails& src) {
  return false;
}
int BaseChatMesh::findChannelIdx(const mesh::GroupChannel& ch) {
  return -1;  // not found
}
#endif

bool BaseChatMesh::getContactByIdx(uint32_t idx, ContactInfo& contact) {
  if (idx >= num_contacts) return false;

  return readContact(idx, contact);
}

ContactsIterator BaseChatMesh::startContactsIterator() {
  return ContactsIterator(MAX_ANON_CONTACTS);   // start at offset, skip the anon entries
}

#ifdef CONTACTS_PAGED
bool ContactsIterator::hasNext(const BaseChatMesh* mesh, ContactInfo& dest, uint32_t since) {
  while (bucket < 256) {
    while (next_idx < mesh->num_contacts) {
      int i = next_idx++;
      if (mesh->cidx[i].key[0] != bucket) continue;
      if (since && mesh->contactLastmod(i) <= since) continue;
      if (mesh->readContact(i, dest)) return true;
    }
    bucket++;
    next_idx = MAX_ANON_CONTACTS;
  }
  return false;
}
#else
bool ContactsIterator::hasNext(const BaseChatMesh* mesh, ContactInfo& dest, uint32_t since) {
  while (next_idx < mesh->getTotalContactSlots()) {
    dest = mesh->contacts[next_idx++];
    if (since == 0 || dest.lastmod > since) return true;
  }
  return false;
}
#endif

void BaseChatMesh::loop() {
#ifdef CONTACTS_PAGED
  c_epoch++;   // contacts used in earlier passes may be evicted from the cache now
#endif
  Mesh::loop();

  if (txt_send_timeout && millisHasNowPassed(txt_send_timeout)) {
    // failed to get an ACK
    onSendTimeout();
    txt_send_timeout = 0;
  }

  if (_pendingLoopback) {
    onRecvPacket(_pendingLoopback);  // loop-back, as if received over radio
    releasePacket(_pendingLoopback);   // undo the obtainNewPacket()
    _pendingLoopback = NULL;
  }
}
