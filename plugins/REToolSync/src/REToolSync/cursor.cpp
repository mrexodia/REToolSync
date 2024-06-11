#include "../../include/REToolSync/cursor.hpp"
#include <DbgEng.h>
#include <Windows.h>

#include "../../include/REToolSync/Extension.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <wininet.h>

mod_set g_ModVec;

std::string Cursor::toHex(uint64_t value) {
  std::stringstream ss;
  ss << "0x" << std::hex << value;
  return ss.str();
}

uint64_t Cursor::fromHex(const std::string &value) {
  uint64_t result;
  std::stringstream ss;
  ss << std::hex << value;
  ss >> result;
  return result;
}

uint64_t Cursor::fromDec(const std::string &value) {
  uint64_t result;
  std::stringstream ss;
  ss << std::dec << value;
  ss >> result;
  return result;
}

std::string Cursor::serialize(int indent) const {
  nlohmann::json j;
  j["toolid"] = tool_id;
  j["architecture"] = architecture;
  j["va"] = toHex(va);
  j["rva"] = toHex(rva);
  j["fileoffset"] = toHex(fileoffset);
  j["filepath"] = filepath;
  j["module"] = module;
  j["sha1"] = sha1;
  j["md5"] = md5;
  j["TimeDateStamp"] = toHex(TimeDateStamp);
  j["loadedbase"] = toHex(loadedbase);
  j["imagebase"] = toHex(imagebase);
  j["imagesize"] = toHex(imagesize);
  return j.dump(indent);
}

bool Cursor::deserialize(const char *json, Cursor &c) {
  auto j = nlohmann::json::parse(json);
  if (!j.is_object()) {
    return false;
  }
  return deserialize(j, c);
}

bool Cursor::deserialize(const nlohmann::json::value_type &j, Cursor &c) {
  try {
    c = Cursor();
    c.tool_id = j["toolid"];
    c.architecture = j["architecture"];
    // c.cursorid = j["cursorid"];
    c.va = Cursor::fromHex(j["va"]);
    c.rva = (uint32_t)Cursor::fromHex(j["rva"]);
    c.fileoffset = Cursor::fromHex(j["fileoffset"]);
    c.filepath = j["filepath"];
    c.sha1 = j["sha1"];
    c.md5 = j["md5"];
    c.module = j["module"];
    c.TimeDateStamp = (uint32_t)Cursor::fromHex(j["TimeDateStamp"]);
    c.loadedbase = Cursor::fromHex(j["loadedbase"]);
    c.imagebase = Cursor::fromHex(j["imagebase"]);
    c.imagesize = (uint32_t)Cursor::fromHex(j["imagesize"]);
  } catch (const nlohmann::json::exception &) {
    return false;
  } catch (const std::invalid_argument &) {
    return false;
  }
  return true;
}

bool Cursor::deserialize(const char *json, std::vector<Cursor> &cs) {
  auto j = nlohmann::json::parse(json);
  if (!j.is_array()) {
    return false;
  }
  cs.reserve(j.size());
  for (const auto &item : j) {
    Cursor c;
    if (!deserialize(item, c)) {
      return false;
    }
    cs.push_back(c);
  }
  return true;
}

std::string get_arch() {
  std::string arch = "x64";
  ULONG proc_type = 0;
  HRESULT hr;

  hr = g_DbgControl->GetActualProcessorType(&proc_type);

  if (FAILED(hr)) {
    return arch;
  }

  switch (proc_type) {
  case IMAGE_FILE_MACHINE_AMD64:
    arch = "x64";
    break;

  case IMAGE_FILE_MACHINE_ARM:
    arch = "arm";
    break;
  case IMAGE_FILE_MACHINE_ARM64:
    arch = "arm64";
    break;

  case IMAGE_FILE_MACHINE_I386:
    arch = "x86";
    break;

  case IMAGE_FILE_MACHINE_IA64:
    arch = "x64";
    break;

  default:
    break;
  }

  return arch;
}

HRESULT GetCurrentInstructionCursor(_Out_ Cursor &c) {
  HRESULT hr = E_FAIL;

  ULONG modIdx = 0;
  char modName[MAX_PATH] = {0};
  hr = g_DbgReg->GetInstructionOffset(&c.va);
  if (FAILED(hr))
    goto Done;

  hr = g_DbgSym->GetModuleByOffset(c.va, 0, &modIdx, &c.imagebase);
  if (FAILED(hr))
    goto Done;
  hr = g_DbgSym->GetModuleNameString(DEBUG_MODNAME_MODULE, modIdx, c.imagebase,
                                     modName, MAX_PATH, nullptr);
  if (FAILED(hr))
    goto Done;

  c.filepath = modName;

  if (c.filepath.find("\\") != std::string::npos) {

    c.module = c.filepath.substr(c.filepath.find_last_of("\\") + 1);
  } else {
    c.module = c.filepath;
  }

  c.rva = static_cast<ULONG>(c.va - c.imagebase);

Done:
  return hr;
}

bool get_cursors() {
  // TODO: do this only once during initialization
  HINTERNET hSession = InternetOpenA("REToolSync", INTERNET_OPEN_TYPE_DIRECT,
                                     nullptr, nullptr, 0);

  if (!hSession)
    Log(LOG_ERROR, "InternetOpenA");
  // InternetCloseHandle

  // TODO: error handling
  HINTERNET hConnection = InternetConnectA(hSession,
                                           "127.0.0.1", // Server
                                           6969,
                                           nullptr, // Username
                                           nullptr, // Password
                                           INTERNET_SERVICE_HTTP,
                                           0,  // Synchronous
                                           0); // No Context
  // InternetCloseHandle

  if (!hConnection)
    Log(LOG_ERROR, "InternetConnectA");

  // TODO: error handling
  PCTSTR rgpszAcceptTypes[] = {"application/json", nullptr};
  HINTERNET hRequest = HttpOpenRequestA(
      hConnection, "GET", "/api/clients",
      nullptr,          // Default HTTP Version
      nullptr,          // No Referer
      rgpszAcceptTypes, // Accept
      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, // Flags
      NULL);                                               // No Context
  // InternetCloseHandle

  if (!hRequest)
    Log(LOG_ERROR, "HttpOpenRequestA");

  // TODO: error handling
  auto bSent = HttpSendRequestA(hRequest,
                                nullptr, // No extra headers
                                0,       // Header length
                                nullptr, 0);

  if (!bSent) {
    Log(LOG_ERROR, "HttpSendRequestA: %x", GetLastError());
  }

  std::string pData;

  DWORD dwContentLen;
  DWORD dwBufLen = sizeof(dwContentLen);
  if (HttpQueryInfoA(hRequest,
                     HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                     (LPVOID)&dwContentLen, &dwBufLen, 0)) {
    // You have a content length so you can calculate percent complete
    pData.resize(dwContentLen);
    DWORD dwReadSize = dwContentLen;
    DWORD dwBytesRead;

    InternetReadFile(hRequest, (char *)pData.data(), dwReadSize,
                     &dwBytesRead); // TODO: error handling
  } else
    Log(LOG_ERROR, "no Content-Length header!");

  if (pData.empty())
    return false;

  Log(LOG_INFO, pData.c_str());
  return deserialize_modvec(pData.c_str(), g_ModVec);
}

bool deserialize_modvec(const char *json, mod_set &mods) {
  auto j = nlohmann::json::parse(json);

  if (!j.is_array()) {
    return false;
  }

  for (auto &[k, v] : j.items()) {
    if (!v.is_object()) {
      continue;
    }

    if (!v.contains(std::string{"module"}) ||
        !v.contains(std::string{"base"})) {
      continue;
    }

    auto mod_name = v["module"].get<std::string>();
    auto mod_addr = v["base"].get<std::string>();
    auto m = mod(mod_name, Cursor::fromHex(mod_addr));

    mods.insert(m);
  }

  return true;
}

bool Cursor::translate_address(Cursor &c, mod &m) {
  bool ret = false;
  Cursor c2;

  if (m.first.empty() || m.second == 0) {
    return ret;
  }
  auto old_va = c.va;
  auto old_base = c.imagebase;

  auto modl =
      std::find_if(g_ModVec.begin(), g_ModVec.end(), [&](const mod &mod) {
        return mod.first.starts_with(m.first);
      });

  if (modl != g_ModVec.end()) {
    c2.module = m.first;
    c2.imagebase = modl->second;
    c2.rva = c.va - c.imagebase;
    c2.va = c2.imagebase + c2.rva;
    c = c2;
    ret = true;
  } else {
    return false;
  }

  return ret;
}