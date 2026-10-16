#pragma once

#include <helpers/IdentityStore.h>
#include <helpers/ContactInfo.h>
#ifdef CONTACTS_PAGED
  #include <helpers/BaseChatMesh.h>   // ContactPageStore
#endif
#include <helpers/ChannelDetails.h>
#include "NodePrefs.h"

class DataStoreHost {
public:
  virtual bool onContactLoaded(const ContactInfo& contact) =0;
  virtual bool getContactForSave(uint32_t idx, ContactInfo& contact) =0;
  virtual bool onChannelLoaded(uint8_t channel_idx, const ChannelDetails& ch) =0;
  virtual bool getChannelForSave(uint8_t channel_idx, ChannelDetails& ch) =0;
};

class DataStore
#ifdef CONTACTS_PAGED
  : public ContactPageStore
#endif
{
  FILESYSTEM* _fs;
  FILESYSTEM* _fsExtra;
  mesh::RTCClock* _clock;
  IdentityStore identity_store;

  void loadPrefsInt(const char *filename, NodePrefs& prefs);
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  void checkAdvBlobFile();
#endif

public:
  DataStore(FILESYSTEM& fs, mesh::RTCClock& clock);
  DataStore(FILESYSTEM& fs, FILESYSTEM& fsExtra, mesh::RTCClock& clock);
  void begin();
  bool formatFileSystem();
  FILESYSTEM* getPrimaryFS() const { return _fs; }
  FILESYSTEM* getSecondaryFS() const { return _fsExtra; }
  bool loadMainIdentity(mesh::LocalIdentity &identity);
  bool saveMainIdentity(const mesh::LocalIdentity &identity);
  void loadPrefs(NodePrefs& prefs);
  bool savePrefs(NodePrefs& prefs);
  void loadContacts(DataStoreHost* host);
#ifdef CONTACTS_PAGED
  // ContactPageStore: one file per first public-key byte, /cN/XX (N = high nibble), 152-byte slots
  bool readContactRec(uint8_t bucket, uint8_t slot, uint8_t rec[CONTACT_REC_SIZE]) override;
  bool writeContactRec(uint8_t bucket, uint8_t slot, const uint8_t rec[CONTACT_REC_SIZE]) override;
  void scanBucket(uint8_t bucket, void (*cb)(void* ctx, uint8_t slot, const uint8_t* rec), void* ctx) override;
  void migrateContactsToPaged();   // one-time: /contacts3 -> bucket files, kept as /contacts3.bak
  void setContactDirPrefix(char p) { _cprefix = p; }   // 'c'; the self-test uses 't'
  void removeContactFiles();       // every bucket file + dir under the current prefix
private:
  char _cprefix = 'c';
public:
#endif
  void saveContacts(DataStoreHost* host, bool (*filter)(const ContactInfo& c) = NULL);
  void loadChannels(DataStoreHost* host);
  void saveChannels(DataStoreHost* host);
  void migrateToSecondaryFS();
  uint8_t getBlobByKey(const uint8_t key[], int key_len, uint8_t dest_buf[]);
  bool putBlobByKey(const uint8_t key[], int key_len, const uint8_t src_buf[], uint8_t len);
  bool deleteBlobByKey(const uint8_t key[], int key_len);
  File openRead(const char* filename);
  File openRead(FILESYSTEM* fs, const char* filename);
  bool removeFile(const char* filename);
  bool removeFile(FILESYSTEM* fs, const char* filename);
  uint32_t getStorageUsedKb() const;
  uint32_t getStorageTotalKb() const;

private:
  FILESYSTEM* _getContactsChannelsFS() const { if (_fsExtra) return _fsExtra; return _fs;};
};
