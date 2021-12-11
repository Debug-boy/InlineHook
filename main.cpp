#include <iostream>
#include <windows.h>
#include <vector>

class InlineHook {
private:
	HANDLE m_handle = nullptr;
	DWORD m_hookAddress = 0UL;
	LPVOID m_remoteAddress = nullptr;

	DWORD m_pre_atttributes = 0UL;
	BYTE m_pre_transferCommand[5]{};

public:
	static const unsigned char HOOK_CMD_CALL = 0xE8;
	static const unsigned char HOOK_CMD_JMP = 0xE9;

private:

	LPVOID remoteAlloc(SIZE_T allocSize) {
		return VirtualAllocEx(m_handle, (LPVOID)(0), allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	BOOL remoteModify(DWORD lfnew_protect, DWORD* previous_protect = nullptr) {
		DWORD local_protect;
		BOOL protecIs = VirtualProtectEx(m_handle, (LPVOID)(m_hookAddress), 5, lfnew_protect, &local_protect);
		if (previous_protect != NULL)
			*previous_protect = local_protect;
		return protecIs;
	}

	void hook_protect_begin() noexcept(false){
		if (!remoteModify(PAGE_EXECUTE_READWRITE, &m_pre_atttributes))
			throw "inlineHook err:modify memory atttribute is failed!";
	}

	void hook_protect_end() noexcept(false) {
		if (!remoteModify(m_pre_atttributes))
			throw "inlineHook err:modify memory atttribute is failed!";
	}

public:

	InlineHook() = default;

	InlineHook(DWORD processId, DWORD hookAddress, SIZE_T allocSize) {
		set(processId, hookAddress, allocSize);
	}

	~InlineHook() {
		if (m_handle)
			CloseHandle(m_handle);
	}

	void set(DWORD processId, DWORD hookAddress, SIZE_T allocSize) {
		m_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		m_hookAddress = hookAddress;
		m_remoteAddress = remoteAlloc(allocSize);
	}

	std::vector<unsigned char>get_transferCommand(unsigned char cmd) {
		auto local_offset = get_transferOffset(m_hookAddress, (DWORD)m_remoteAddress);
		auto local_jumpBytes = (unsigned char*)(&local_offset);
		auto local_bytes = std::vector<unsigned char>(local_jumpBytes, local_jumpBytes + 4);
		local_bytes.insert(local_bytes.begin(), cmd);
		return local_bytes;
	}

	bool run(std::vector<unsigned char>shellCode, unsigned char transfer_cmd = HOOK_CMD_CALL) {

		try {
			if (!m_hookAddress)
				throw "inlineHook err:un set HookAddress!";

			if (!m_handle)
				throw "inlineHook err:un OpenProcess,please set target!";

			if (!m_remoteAddress)
				throw "inlineHook err:remote jump address is nullptr!";

			hook_protect_begin();

			//if m_pre_transferCommand is void,copy current command bytes to m_pre_transferCommand;
			if(!*m_pre_transferCommand)
				ReadProcessMemory(m_handle, (LPVOID)(m_hookAddress), (LPVOID)(m_pre_transferCommand), sizeof(m_pre_transferCommand), NULL);

			WriteProcessMemory(m_handle, (LPVOID)(m_remoteAddress), (LPVOID)(shellCode.begin()._Ptr), shellCode.size(), nullptr);

			auto transfer_command = get_transferCommand(transfer_cmd);
			WriteProcessMemory(m_handle, (LPVOID)(m_hookAddress), (LPVOID)(transfer_command.begin()._Ptr), transfer_command.size(), nullptr);

			hook_protect_end();

		}
		catch (const char* e) {
			std::cout << e << std::endl;
			return false;
		}

		return true;
	}

	bool restore() {
		if (*m_pre_transferCommand) {
			try {
				hook_protect_begin();
				WriteProcessMemory(m_handle, (LPVOID)(m_hookAddress), (LPVOID)(m_pre_transferCommand), sizeof(m_pre_transferCommand), NULL);
				hook_protect_end();
			}
			catch (const char* e) {
				std::cout << e << std::endl;
				return false;
			}
		}
		return true;
	}

	DWORD get_hookAddr() const {
		return m_hookAddress;
	}

	static DWORD get_transferOffset(DWORD current_address, DWORD jump_address) {
		return jump_address - (current_address + 5UL);
	}
};


int main(int argc, char* argv[], char* envp[]) {


	auto shellCode = std::vector<unsigned char>({
		0x55,0x8B ,0xEC ,0x8A ,0x45 ,0x08 ,0x80 ,0x7D ,0x08 ,0x20 ,0x7C ,0x08 ,0x80 ,0x7D
	,0x08 ,0x61 ,0x7F ,0x02 ,0x2C ,0x20 ,0x5D ,0xC3 ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,
	0xCC ,0xCC ,0xCC ,0xCC });


	InlineHook mHook(0x7474, 0x00E7108E, 0x100);
	if (mHook.run(shellCode, InlineHook::HOOK_CMD_CALL))
		std::cout << "hook succedd!" << std::endl;
	
	if(mHook.restore())
		std::cout << "hook restore succedd!" << std::endl;
}