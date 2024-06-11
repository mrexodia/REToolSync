#include <DbgEng.h>
#include <Windows.h>
#include <handleapi.h>
#include <memory>
#include <minwindef.h>
#include <processthreadsapi.h>
#include <string>
#include <strsafe.h>
#include <synchapi.h>
#include <utility>
#include <winbase.h>
#include <wininet.h>
#include <winnt.h>
#include <wrl/client.h> // ComPtr

//

#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

//

#include "../../include/REToolSync/Extension.hpp"
#include "../../include/REToolSync/cursor.hpp"
#include "../../include/easywsclient.hpp"

#pragma comment(lib, "dbgeng.lib")
#pragma comment(lib, "wininet.lib")

using Microsoft::WRL::ComPtr;

std::unique_ptr<easywsclient::WebSocket> ws;

ComPtr<IDebugClient5> g_DbgClient = nullptr;
ComPtr<IDebugControl5> g_DbgControl = nullptr;
ComPtr<IDebugRegisters> g_DbgReg = nullptr;
ComPtr<IDebugEventCallbacks> g_DbgEventCallbacks = nullptr;
ComPtr<IDebugSymbols3> g_DbgSym = nullptr;
Cursor g_CurrentStateCursor;
Cursor g_PrevCursor;
HANDLE g_Mutex;
HANDLE g_ThreadHandle = INVALID_HANDLE_VALUE;
BOOLEAN g_StopThread = false;

/*
// TODO: Fix this
class EventCallbacks : public IDebugEventCallbacks {
public:
  STDMETHOD_(ULONG, AddRef)() { return 1; }
  STDMETHOD_(ULONG, Release)() { return 0; }

  STDMETHOD(QueryInterface)(REFIID InterfaceId, PVOID *Interface) {
    if (IsEqualIID(InterfaceId, __uuidof(IDebugEventCallbacks))) {
      *Interface = (IDebugEventCallbacks *)this;
      return S_OK;
    } else {
      *Interface = nullptr;
      return E_NOINTERFACE;
    }
  }

  STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT Bp) { return DEBUG_STATUS_NO_CHANGE; }
  STDMETHOD(Exception)(PEXCEPTION_RECORD64 Exception, ULONG FirstChance) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(CreateThread)
  (ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(ExitThread)(ULONG ExitCode) { return DEBUG_STATUS_NO_CHANGE; }
  STDMETHOD(CreateProcess)
  (ULONG64 ImageFileHandle, ULONG64 Handle, ULONG64 BaseOffset,
   ULONG ModuleSize, PCSTR ModuleName, PCSTR ImageName, ULONG CheckSum,
   ULONG TimeDateStamp, ULONG64 InitialThreadHandle, ULONG64 ThreadDataOffset,
   ULONG64 StartOffset) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(ExitProcess)(ULONG ExitCode) { return DEBUG_STATUS_NO_CHANGE; }
  STDMETHOD(LoadModule)
  (ULONG64 ImageFileHandle, ULONG64 BaseOffset, ULONG ModuleSize,
   PCSTR ModuleName, PCSTR ImageName, ULONG CheckSum, ULONG TimeDateStamp) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(UnloadModule)(PCSTR ImageBaseName, ULONG64 BaseOffset) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(SystemError)(ULONG Error, ULONG Level) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(SessionStatus)(ULONG Status) { return DEBUG_STATUS_NO_CHANGE; }
  STDMETHOD(ChangeDebuggeeState)(ULONG Flags, ULONG64 Argument) {
    return DEBUG_STATUS_NO_CHANGE;
  }
  STDMETHOD(ChangeEngineState)(ULONG Flags, ULONG64 Argument) {
    if (Flags & DEBUG_CES_EXECUTION_STATUS) {
      ULONG executionStatus;
      if (g_DbgControl->GetExecutionStatus(&executionStatus) == S_OK &&
          (executionStatus == DEBUG_STATUS_STEP_OVER ||
           executionStatus == DEBUG_STATUS_BREAK)) {
        // ULONG64 rip;

        if (GetCurrentInstructionCursor(g_CurrentStateCursor) == S_OK) {
          g_Mutex.lock();
          Cursor TranslatedCursor = g_CurrentStateCursor;
          auto mod = std::make_pair(g_CurrentStateCursor.module,
                                    g_CurrentStateCursor.imagebase);
          Cursor::translate_address(TranslatedCursor, mod);
          nlohmann::json j;
          j["request"] = "goto";
          j["address"] = TranslatedCursor.va;
          ws->send(j.dump());
          g_Mutex.unlock();
        }
      }
    }
    return DEBUG_STATUS_NO_CHANGE;
  }

  STDMETHOD(GetInterestMask)(PULONG Mask) {
    *Mask = DEBUG_EVENT_CHANGE_ENGINE_STATE;
    return S_OK;
  }

  STDMETHOD(ChangeSymbolState)(ULONG Flags, ULONG64 Argument) {
    return DEBUG_STATUS_NO_CHANGE;
  }
};

EventCallbacks g_EventCallbacks;
*/

void ReconnectWebsocket(); // Forward declaration
DWORD __stdcall WebSocketThreadProc(LPVOID Unused) {
  UNREFERENCED_PARAMETER(Unused);
  WaitForSingleObject(g_Mutex, INFINITE);
  ws.reset(easywsclient::WebSocket::from_url(
      "ws://localhost:6969/REToolSync", {},
      "WinDbg " + std::to_string(GetCurrentProcessId())));

  ReleaseMutex(g_Mutex);
  const DWORD pollTime = 200; // 200 MS ?
  DWORD sendTime = GetTickCount();
  Cursor localCursor;

  if (ws != nullptr) {
    LOG(LOG_DEBUG, "Connected to server!");
  }

  while (ws->getReadyState() != easywsclient::WebSocket::CLOSED) {
    WaitForSingleObject(g_Mutex, INFINITE);
    ws->poll(20);
    ws->dispatch([](const std::string &message) {
      Log(LOG_DEBUG, "Received message: %s", message.c_str());
    });
    ReleaseMutex(g_Mutex);
  }

  if (ws->getReadyState() == easywsclient::WebSocket::CLOSED) {
    LOG(LOG_DEBUG, "Disconnected from server!");
  }
  ReconnectWebsocket();
  return 0;
}

void ReconnectWebsocket() {
  CloseHandle(g_Mutex);
  LOG(LOG_DEBUG, "Reconnecting to server!");
  std::this_thread::sleep_for(std::chrono::seconds(3));
  g_ThreadHandle =
      CreateThread(nullptr, 0, WebSocketThreadProc, nullptr, 0, nullptr);
}

HRESULT IsIgnoreableEvent(BOOL *bIgnore) {
  HRESULT hr;
  ULONG Type, ProcessId, ThreadId, BreakpointId, ExtraInformationUsed,
      CommandSize;
  PDEBUG_BREAKPOINT Breakpoint;

  hr = g_DbgControl->GetLastEventInformation(
      &Type, &ProcessId, &ThreadId, &BreakpointId, sizeof(ULONG),
      &ExtraInformationUsed, NULL, NULL, NULL);

  if (FAILED(hr))
    goto Done;

  switch (Type) {
  case DEBUG_EVENT_CHANGE_SYMBOL_STATE:
  case DEBUG_EVENT_UNLOAD_MODULE:
  case DEBUG_EVENT_LOAD_MODULE:
  case DEBUG_EVENT_CREATE_PROCESS:
  case DEBUG_EVENT_EXIT_PROCESS:
  case DEBUG_EVENT_CREATE_THREAD:
  case DEBUG_EVENT_EXIT_THREAD:
  case DEBUG_EVENT_SYSTEM_ERROR:
    *bIgnore = TRUE;
    break;
  case DEBUG_EVENT_BREAKPOINT:
    *bIgnore = FALSE;
    hr = g_DbgControl->GetBreakpointById(BreakpointId, &Breakpoint);
    if (FAILED(hr))
      goto Done;

    /*
        hr = Breakpoint->GetCommand(, ULONG BufferSize, PULONG CommandSize);
        if (FAILED(hr))
          goto Done;
    *bIgnore = CommandSize == 0;
    */
    break;
  }
Done:

  return hr;
}

bool RequestGoto(std::string address) {
  bool ret = false;
  HINTERNET hInternet =
      InternetOpenA("REToolSync", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

  std::string postData = "address=" + address;

  if (hInternet == NULL) {
    return ret;
  }

  HINTERNET hConnect = InternetConnectA(hInternet, "localhost", 6969, nullptr,
                                        nullptr, INTERNET_SERVICE_HTTP, 0, 0);

  PCTSTR rgpszAcceptTypes[] = {"application/x-www-form-urlencoded", nullptr};
  HINTERNET hRequest = HttpOpenRequestA(
      hConnect, "POST", std::string{"/api/goto?" + postData}.c_str(), nullptr,
      nullptr, rgpszAcceptTypes,
      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);

  if (hRequest == NULL) {
    return ret;
  }
  ret = HttpSendRequestA(hRequest, nullptr, 0, (LPVOID)postData.c_str(),
                         postData.size());
Done:
  InternetCloseHandle(hRequest);
  InternetCloseHandle(hConnect);
  InternetCloseHandle(hInternet);
  return ret;
}

HRESULT InitGlobals() {
  HRESULT hr = S_OK;

  hr = DebugCreate(__uuidof(IDebugClient5), (void **)&g_DbgClient);
  if (FAILED(hr)) {
    return hr;
  }

  hr = DebugCreate(__uuidof(IDebugControl5), (void **)&g_DbgControl);
  if (FAILED(hr)) {
    return hr;
  }

  hr = DebugCreate(__uuidof(IDebugRegisters), (void **)&g_DbgReg);

  if (FAILED(hr)) {
    return hr;
  }

  hr = DebugCreate(__uuidof(IDebugSymbols3), (void **)&g_DbgSym);
  if (FAILED(hr)) {
    return hr;
  }

  /*
  hr = g_DbgClient->SetEventCallbacks(&g_EventCallbacks);
  if (FAILED(hr)) {
    return hr;
  }*/

  return hr;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
    DebugExtensionInitialize(PULONG Version, PULONG Flags) {
  *Version = DEBUG_EXTENSION_VERSION(1, 0);
  *Flags = 0;
  PDEBUG_EVENT_CALLBACKS callbacks = nullptr;

  HRESULT hr = InitGlobals();
  if (FAILED(hr)) {
    return hr;
  }

  g_Mutex = CreateMutex(nullptr, FALSE, nullptr);

  g_ThreadHandle =
      CreateThread(nullptr, 0, WebSocketThreadProc, nullptr, 0, nullptr);

  LOG(LOG_DEBUG, "Extension Loaded!");

  if (FAILED(hr)) {
    return hr;
  }

  // hr = g_DbgClient->SetEventCallbacks(&g_EventCallbacks);

  hr = g_DbgClient->GetEventCallbacks(&callbacks);

  if (FAILED(hr)) {
    return hr;
  }

  auto ret = get_cursors();

  if (ret == false) {
    return E_FAIL;
  }

  /*
  if (callbacks->QueryInterface(__uuidof(IDebugEventCallbacks),
                                (void **)&g_EventCallbacks) != S_OK) {
    return E_NOINTERFACE;
  }
  */

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
    DebugExtensionNotify(ULONG Notify, ULONG64 Argument) {

  switch (Notify) {
  case DEBUG_NOTIFY_SESSION_ACTIVE:
    break;
  case DEBUG_NOTIFY_SESSION_INACTIVE:
    break;
  case DEBUG_NOTIFY_SESSION_ACCESSIBLE: {
    BOOL bIgnore = FALSE;
    if (IsIgnoreableEvent(&bIgnore)) {
      break;
    }
    if (SUCCEEDED(GetCurrentInstructionCursor(g_CurrentStateCursor))) {
      WaitForSingleObject(g_Mutex, INFINITE);
      Cursor TranslatedCursor = g_CurrentStateCursor;
      auto mod = std::make_pair(g_CurrentStateCursor.module,
                                g_CurrentStateCursor.imagebase);
      Cursor::translate_address(TranslatedCursor, mod);
      nlohmann::json j;
      j["request"] = "goto";
      j["address"] = Cursor::toHex(TranslatedCursor.va);
      ws->send(j.dump());
      RequestGoto(j["address"].get<std::string>());
      ReleaseMutex(g_Mutex);
    }
  } break;
  default:
    break;
  }
  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK DebugExtensionUninitialize() {
  LOG(LOG_DEBUG, "Extension Unloaded!");

  g_DbgControl->Release();
  g_DbgClient->Release();
  // g_EventCallbacks.Release();
  g_DbgReg->Release();
  g_StopThread = true;

  ws->close();

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
    retoolsync(PDEBUG_CLIENT4 Client, PCSTR args) {
  UNREFERENCED_PARAMETER(Client);
  UNREFERENCED_PARAMETER(args);

  HRESULT hr;
  auto b = get_cursors();
  if (FAILED(GetCurrentInstructionCursor(g_CurrentStateCursor))) {
    return E_FAIL;
  }

  if (!b) {
    LOG(LOG_ERROR, "Error fetching cursor");
  }

  return S_OK;
}