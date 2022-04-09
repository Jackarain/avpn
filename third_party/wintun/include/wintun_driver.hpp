#pragma once
class wintun_driver
{
public:
	static DWORD tap_delete_adapter(
			_In_opt_ HWND hwndParent,
			_In_ LPCGUID pguidAdapter,
			_Inout_ LPBOOL pbRebootRequired);
	static DWORD tap_create_adapter(
			_In_opt_ HWND hwndParent,
			_In_opt_ LPCTSTR szDeviceDescription,
			_In_ LPCTSTR szHwId,
			_Inout_ LPBOOL pbRebootRequired,
			_Out_ LPGUID pguidAdapter);
	static DWORD tap_set_adapter_name(
			_In_ LPCGUID pguidAdapter,
			_In_ LPCTSTR szName,
			_In_ BOOL bSilent);
};

