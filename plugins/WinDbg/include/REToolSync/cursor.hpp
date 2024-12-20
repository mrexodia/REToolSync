#include "../json.hpp"
#include <iostream>
#include <set>

#include <Windows.h>

using mod = std::pair<std::string, uint64_t>;
using mod_set = std::set<mod>;

extern mod_set g_ModVec;

class Cursor {
  /*
   *
def get_static_info():
  # This is the desired structure
  return {
          'path': '',

          'module': '',
          'base': hex(0),
          'size': hex(0),
          'md5': '',
          'sha256': '',
          'crc32': hex(0),
          'filesize': hex(0),
  }
   */
public:
  std::string tool_id = "windbg";
  std::string architecture;
  // actual information
  uint64_t va = -1;
  uint32_t rva = -1;
  uint64_t fileoffset = -1;

  // metadata
  std::string filepath;
  std::string module;
  std::string sha1;
  std::string md5;
  uint32_t TimeDateStamp = -1;
  uint64_t loadedbase = -1; // image base as loaded in memory
  uint64_t imagebase = -1;  // image base in the header
  uint32_t imagesize = -1;

  static bool translate_address(Cursor &c, mod &m);

  static uint64_t fromHex(const std::string &text);

  static uint64_t fromDec(const std::string &text);

  static std::string toHex(uint64_t value);

  std::string serialize(int indent = -1) const;
  static bool deserialize(const nlohmann::json::value_type &j, Cursor &c);
  // static bool deserialize(const nlohmann::json::value_type& j, Cursor& c); ;
  static bool deserialize(const char *json, Cursor &c);
  static bool deserialize(const char *json, std::vector<Cursor> &cs);

  Cursor() = default;
};

bool get_cursors();
bool deserialize_modvec(const char *json, mod_set &mods);

HRESULT GetCurrentInstructionCursor(_Out_ Cursor &c);