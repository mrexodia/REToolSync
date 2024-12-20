#pragma once
#include <DbgEng.h>
#include <DbgHelp.h>
#include <strsafe.h>
#include <wrl/client.h>

#include <cstdint>

// #include "REToolSync/Extension.h"
// #include "cursor.h"

#define EXTENSION_NAME "REToolSync"

HRESULT InitGlobals();

extern Microsoft::WRL::ComPtr<IDebugControl5> g_DbgControl;
extern Microsoft::WRL::ComPtr<IDebugClient5> g_DbgClient;
extern Microsoft::WRL::ComPtr<IDebugAdvanced4> g_DbgAdv;
extern Microsoft::WRL::ComPtr<IDebugRegisters> g_DbgReg;
extern Microsoft::WRL::ComPtr<IDebugSymbols3> g_DbgSym;
extern CRITICAL_SECTION g_CritSection;
extern HANDLE g_WsThreadHandle;

// extern Cursor g_CurrentStateCursor;

enum LogLevel {
  LOG_ERROR = 0,
  LOG_WARNING = 1,
  LOG_INFO = 2,
  LOG_DEBUG = 3,
};

#define LOG(level, ...) Log(level, __VA_ARGS__)

inline void Log(LogLevel level, const char *format, ...) {
#if _DEBUG
  va_list args;
  va_start(args, format);
  char buffer[1024];
  StringCchVPrintf(buffer, 1024, format, args);
  va_end(args);

  switch (level) {
  case LOG_ERROR:
    g_DbgControl->Output(DEBUG_OUTPUT_NORMAL, "[%s !] %s\n", EXTENSION_NAME,
                         buffer);
    break;

  case LOG_WARNING:
    g_DbgControl->Output(DEBUG_OUTPUT_NORMAL, "[%s *] %s\n", EXTENSION_NAME,
                         buffer);
    break;

  case LOG_INFO:
    g_DbgControl->Output(DEBUG_OUTPUT_NORMAL, "[%s +] %s\n", EXTENSION_NAME,
                         buffer);
    break;

  case LOG_DEBUG:
    g_DbgControl->Output(DEBUG_OUTPUT_NORMAL, "[%s ?] %s\n", EXTENSION_NAME,
                         buffer);
    break;
  }
#endif
}