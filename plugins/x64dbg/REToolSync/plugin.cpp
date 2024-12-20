#include "plugin.h"
#include <random>
#include <cmath>
#include "sha1.hpp"
#include "stringutils.h"
#include <atomic>
#include <unordered_map>
#include "json.hpp"
#include <wininet.h>
#include <cinttypes>
#include "easywsclient.hpp"

using easywsclient::WebSocket;

static HANDLE hWebSocketThread;
static std::atomic_bool bStopWebSocketThread;
static char endpoint[128];

static std::string md5file(const wchar_t* path)
{
	std::string md5;
	auto hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		HCRYPTPROV hProv;
		if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			HCRYPTHASH hHash;
			if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			{
				BYTE rgbFile[1024];
				BOOL bResult = TRUE;
				DWORD cbRead = 0;
				while (bResult = ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL))
				{
					if (0 == cbRead)
					{
						break;
					}

					if (!CryptHashData(hHash, rgbFile, cbRead, 0))
					{
						auto dwStatus = GetLastError();
						dprintf("CryptHashData failed: %d\n", dwStatus);
						CryptReleaseContext(hProv, 0);
						CryptDestroyHash(hHash);
						CloseHandle(hFile);
						return {};
					}
				}

				BYTE rgbHash[16];
				DWORD cbHash = sizeof(rgbHash);
				if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
				{
					CHAR rgbDigits[] = "0123456789abcdef";
					//printf("MD5 hash of file %s is: ", filename);
					for (DWORD i = 0; i < cbHash; i++)
					{
						char b[3] = "";
						sprintf_s(b, "%c%c",
							rgbDigits[rgbHash[i] >> 4],
							rgbDigits[rgbHash[i] & 0xf]
						);
						md5 += b;
					}
				}
				else
				{
					auto dwStatus = GetLastError();
					dprintf("CryptGetHashParam failed: %d\n", dwStatus);
					return {};
				}

				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hProv, 0);
		}
		CloseHandle(hFile);
	}
	return md5;
}

#pragma comment(lib, "wininet.lib")

struct Cursor
{
	// generic metadata
	std::string toolid = "x64dbg";
#ifdef _WIN64
	std::string architecture = "x64";
#else
	std::string architecture = "x86";
#endif
	std::string cursorid; // string that describes which cursor this is (dump/disassembly/decompiler/etc)

	// actual information
	uint64_t va = -1;
	uint32_t rva = -1;
	uint64_t fileoffset = -1;

	// metadata
	std::string filepath;
	std::string sha1;
	std::string md5;
	uint32_t TimeDateStamp = -1;
	uint64_t loadedbase = -1; // image base as loaded in memory
	uint64_t imagebase = -1; // image base in the header
	uint32_t imagesize = -1;

	void dump() const
	{
		//dputs(serialize(2).c_str());
	}

	static std::string toHex(uint64_t value)
	{
		char text[32];
		sprintf_s(text, "0x%llx", value);
		return text;
	}

	static uint64_t fromHex(const std::string& text)
	{
		uint64_t value = 0;
		if (sscanf_s(text.c_str(), "0x%" SCNx64, &value) != 1 && sscanf_s(text.c_str(), "%" SCNx64, &value) != 1)
			throw std::invalid_argument("fromHex failed");
		return value;
	}

	static uint64_t fromDec(const std::string& text)
	{
		uint64_t value = 0;
		if (sscanf_s(text.c_str(), "%" SCNu64, &value) != 1)
			throw std::invalid_argument("fromDec failed");
		return value;
	}

	std::string serialize(int indent = -1) const
	{
		nlohmann::json j;
		j["toolid"] = toolid;
		j["architecture"] = architecture;
		j["cursorid"] = cursorid;
		j["va"] = toHex(va);
		j["rva"] = toHex(rva);
		j["fileoffset"] = toHex(fileoffset);
		j["filepath"] = filepath;
		j["sha1"] = sha1;
		j["md5"] = md5;
		j["TimeDateStamp"] = toHex(TimeDateStamp);
		j["loadedbase"] = toHex(loadedbase);
		j["imagebase"] = toHex(imagebase);
		j["imagesize"] = toHex(imagesize);
		return j.dump(indent);
	}

	static bool deserialize(const nlohmann::json::value_type& j, Cursor& c)
	{
		try
		{
			c = Cursor();
			c.toolid = j["toolid"];
			c.architecture = j["architecture"];
			c.cursorid = j["cursorid"];
			c.va = fromHex(j["va"]);
			c.rva = (uint32_t)fromHex(j["rva"]);
			c.fileoffset = fromHex(j["fileoffset"]);
			c.filepath = j["filepath"];
			c.sha1 = j["sha1"];
			c.md5 = j["md5"];
			c.TimeDateStamp = (uint32_t)fromHex(j["TimeDateStamp"]);
			c.loadedbase = fromHex(j["loadedbase"]);
			c.imagebase = fromHex(j["imagebase"]);
			c.imagesize = (uint32_t)fromHex(j["imagesize"]);
		}
		catch (const nlohmann::json::exception&)
		{
			return false;
		}
		catch (const std::invalid_argument&)
		{
			return false;
		}
		return true;
	}

	static bool deserialize(const char* json, Cursor& c)
	{
		auto j = nlohmann::json::parse(json);
		if (!j.is_object())
			return false;
		return deserialize(j, c);
	}

	static bool deserialize(const char* json, std::vector<Cursor>& cs)
	{
		auto j = nlohmann::json::parse(json);
		if (!j.is_array())
			return false;
		cs.reserve(j.size());
		for (const auto& item : j)
		{
			Cursor c;
			if (!deserialize(item, c))
				return false;
			cs.push_back(c);
		}
		return true;
	}
};

static CRITICAL_SECTION crModules;
static std::unordered_map<duint, Cursor> modules;

static void getCursorPeData(const wchar_t* filename, Cursor& c)
{
	HANDLE hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		IMAGE_DOS_HEADER idh;
		memset(&idh, 0, sizeof(idh));
		DWORD read = 0;
		if (ReadFile(hFile, &idh, sizeof(idh), &read, nullptr))
		{
			if (idh.e_magic == IMAGE_DOS_SIGNATURE)
			{
				if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN))
				{
					IMAGE_NT_HEADERS nth;
					memset(&nth, 0, sizeof(nth));
					//IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
					if (ReadFile(hFile, &nth, sizeof(nth) - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES, &read, nullptr))
					{
						if (nth.Signature == IMAGE_NT_SIGNATURE)
						{
							c.TimeDateStamp = nth.FileHeader.TimeDateStamp;
							c.imagebase = nth.OptionalHeader.ImageBase;
							c.imagesize = nth.OptionalHeader.SizeOfImage;
						}
					}
				}
			}
		}
		CloseHandle(hFile);
	}
}

static void getCursorData(duint base, Cursor& c)
{
	char modpath[MAX_PATH] = "";
	Script::Module::PathFromAddr(base, modpath);
	c.filepath = modpath;

	auto wmodpath = Utf8ToUtf16(modpath);
	{
		SHA1 sha1;
		c.sha1 = sha1.from_file(wmodpath.c_str());
		c.md5 = md5file(wmodpath.c_str());
	}

	c.loadedbase = base;

	getCursorPeData(wmodpath.c_str(), c);
}

static void getModBaseCursor(duint base, Cursor& c)
{
	EnterCriticalSection(&crModules);
	auto found = modules.find(base);
	if (found == modules.end())
	{
		LeaveCriticalSection(&crModules);

		getCursorData(base, c);

		EnterCriticalSection(&crModules);
		modules[base] = c;
		LeaveCriticalSection(&crModules);
	}
	else
	{
		c = found->second;
		LeaveCriticalSection(&crModules);
	}
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
	EnterCriticalSection(&crModules);
	modules.clear();
	LeaveCriticalSection(&crModules);
}

PLUG_EXPORT void CBLOADDLL(CBTYPE cbType, PLUG_CB_LOADDLL* info)
{
	// TODO: move to a worker thread
	Cursor c;
	getModBaseCursor((duint)info->LoadDll->lpBaseOfDll, c);
}

PLUG_EXPORT void CBUNLOADDLL(CBTYPE cbType, PLUG_CB_UNLOADDLL* info)
{
	EnterCriticalSection(&crModules);
	modules.erase((duint)info->UnloadDll->lpBaseOfDll);
	LeaveCriticalSection(&crModules);
}

static bool updateCursor(GUISELECTIONTYPE hWindow, Cursor& c)
{
	if (DbgIsDebugging())
	{
		SELECTIONDATA cursel;
		GuiSelectionGet(hWindow, &cursel);
		if (cursel.start != c.va)
		{
			auto modbase = Script::Module::BaseFromAddr(cursel.start);
			getModBaseCursor(modbase, c);
			c.va = cursel.start;
			c.rva = uint32_t(c.va - modbase);
			if (DbgFunctions())
				c.fileoffset = DbgFunctions()->VaToFileOffset(c.va);
			return true;
		}
	}
	return false;
}

template<typename... Args>
void cmd(const char* format, Args... args)
{
	char command[256] = "";
	_snprintf_s(command, _TRUNCATE, format, args...);
	dprintf("cmd(%s)\n", command);
	DbgCmdExecDirect(command);
}

static void requestGoto(duint address)
{
	dprintf("goto %p\n", address);
	const Cursor* foundModule = nullptr;
	auto mainbase = Script::Module::GetMainModuleBase();
	duint basereloc = 0;
	EnterCriticalSection(&crModules);
	for (const auto& itr : modules)
	{
		const auto& mod = itr.second;
		if (address >= mod.loadedbase && address < mod.loadedbase + mod.imagesize)
		{
			// Matches the loaded base in memory
			foundModule = &mod;
			basereloc = mod.loadedbase;
		}
		else if (address >= mod.imagebase && address < mod.imagebase + mod.imagesize)
		{
			// Matches the image base on disk
			foundModule = &mod;
			basereloc = mod.imagebase;
		}
		if (foundModule != nullptr && foundModule->loadedbase == mainbase)
			break;
	}
	LeaveCriticalSection(&crModules);
	if (foundModule == nullptr)
		throw std::runtime_error("Faild to find module!");
	dprintf("found %s %p %p\n", foundModule->filepath.c_str(), foundModule->loadedbase, basereloc);
	auto rva = address - basereloc;
	auto va = foundModule->loadedbase + rva;
	cmd("disasm 0x%p", va);
	cmd("dump 0x%p", va);
}

static DWORD WINAPI WebSocketThread(LPVOID)
{
	auto url = std::string("ws://") + endpoint + "/REToolSync";
	auto userAgent = "REToolSync x64dbg " + std::to_string(GetCurrentProcessId());
	dprintf("Connecting to %s\n", url.c_str());
	std::unique_ptr<WebSocket> ws(WebSocket::from_url(url, {}, userAgent));
	if (!ws)
	{
		dprintf("Failed to connect\n");
		return 0;
	}
	dprintf("Successfully connected to %s\n", url.c_str());

	Cursor cursor; // TODO: keep track of multiple
	DWORD sendTime = GetTickCount();
	const DWORD cursorPollTime = 200;

	// TODO: implement reconnecting
	while (ws->getReadyState() != WebSocket::CLOSED)
	{
		if (GetTickCount() - sendTime > cursorPollTime)
		{
			if (updateCursor(GUI_DISASSEMBLY, cursor))
			{
				cursor.dump();
				auto json = cursor.serialize();

				Cursor c2;
				if (!Cursor::deserialize(json.c_str(), c2))
					dputs("deserialize");
				if (json != c2.serialize())
				{
					dputs("round trip failed...");
					//dputs(c2.serialize().c_str());
				}

				ws->send(json);
			}
			sendTime = GetTickCount();
		}
		ws->poll(20);
		ws->dispatch([](const std::string& message)
		{
			dprintf("message: %s\n", message.c_str());
			try
			{
				auto j = nlohmann::json::parse(message);
				auto request = j["request"].get<std::string>();
				if (request == "goto")
				{
					auto data = j["address"].get<std::string>();
					auto address = Cursor::fromHex(data);
					requestGoto(address);
				}
			}
			catch (std::exception& x)
			{
				dprintf("exception: %s\n", x.what());
			}
		});
		if (bStopWebSocketThread && ws->getReadyState() != WebSocket::CLOSING)
			ws->close();
	}
	return 0;
}

static bool getCursors(std::vector<Cursor>& cs)
{
	// TODO: do this only once during initialization
	HINTERNET hSession = InternetOpenA("REToolSync",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	if (!hSession)
		dputs("InternetOpenA");
	//InternetCloseHandle

	//TODO: error handling
	HINTERNET hConnection = InternetConnectA(hSession,
		"sync.mrexodia.re",  // Server
		INTERNET_DEFAULT_HTTPS_PORT,
		NULL,     // Username
		NULL,     // Password
		INTERNET_SERVICE_HTTP,
		0,        // Synchronous
		NULL);    // No Context
	//InternetCloseHandle

	if (!hConnection)
		dputs("InternetConnectA");

	//TODO: error handling
	PCTSTR rgpszAcceptTypes[] = { "application/json", nullptr };
	HINTERNET hRequest = HttpOpenRequestA(hConnection,
		"GET",
		"/cursor/blub",
		NULL,    // Default HTTP Version
		NULL,    // No Referer
		rgpszAcceptTypes, // Accept
		INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, // Flags
		NULL);   // No Context
	//InternetCloseHandle

	if (!hRequest)
		dputs("HttpOpenRequestA");

	//TODO: error handling
	auto bSent = HttpSendRequestA(hRequest,
		NULL,    // No extra headers
		0,       // Header length
		NULL,
		0);

	if (!bSent)
		dputs("HttpSendRequestA");

	std::string pData;

	DWORD dwContentLen;
	DWORD dwBufLen = sizeof(dwContentLen);
	if (HttpQueryInfoA(hRequest,
		HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
		(LPVOID)&dwContentLen,
		&dwBufLen,
		0))
	{
		// You have a content length so you can calculate percent complete
		pData.resize(dwContentLen);
		DWORD dwReadSize = dwContentLen;
		DWORD dwBytesRead;

		InternetReadFile(hRequest, (char*)pData.data(), dwReadSize, &dwBytesRead); //TODO: error handling
	}
	else
		dputs("no Content-Length header!");

	if (pData.empty())
		return false;

	//dputs(pData.c_str());
	return Cursor::deserialize(pData.c_str(), cs);
}

static bool cbCommand(int argc, char* argv[])
{
	std::vector<Cursor> cs;
	if (!getCursors(cs))
		dputs("getCursors");
	for (const auto& c : cs)
		c.dump();
	return true;
}

static uint64_t rand64()
{
	std::random_device rd;
	std::mt19937_64 e2(rd());
	std::uniform_int_distribution<long long int> dist(std::llround(std::pow(2, 61)), std::llround(std::pow(2, 62)));
	return dist(e2);
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	// Get the endpoint from the environment
	if (!GetEnvironmentVariableA("RETOOLSYNC_ENDPOINT", endpoint, _countof(endpoint)) || !*endpoint)
		strcpy_s(endpoint, "127.0.0.1:6969");

	// Initialize WinSock
	{
		INT rc;
		WSADATA wsaData;

		rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (rc) {
			dprintf("WSAStartup Failed.\n");
			return 1;
		}
	}

	InitializeCriticalSection(&crModules);
	hWebSocketThread = CreateThread(nullptr, 0, WebSocketThread, nullptr, 0, nullptr);
	_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbCommand, false);
	return !!hWebSocketThread;
}

void pluginStop()
{
	bStopWebSocketThread = true;
	WaitForSingleObject(hWebSocketThread, INFINITE);
	CloseHandle(hWebSocketThread);

	EnterCriticalSection(&crModules);
	modules.clear();
	DeleteCriticalSection(&crModules);
}

void pluginSetup()
{
}
