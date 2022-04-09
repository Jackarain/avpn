#include <Windows.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <ndisguid.h>
#include <SetupAPI.h>
#include <IPExport.h>
#include <Shlwapi.h>
#include <devioctl.h>
#include <wchar.h>
#include <guiddef.h>
#include <initguid.h> /* Keep these two at bottom in this order, so that we only generate extra GUIDs for devpkey. The other keys we'll get from uuid.lib like usual. */
#include <devpkey.h>
#include <newdev.h>

#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Newdev.lib")

#include <tchar.h>

#include <type_traits>

#include "wintun_driver.hpp"

template<class T>
class scoped_exit
{
public:
	explicit scoped_exit(T&& f) : f_(std::move(f)), dismiss_(false) {}
	explicit scoped_exit(const T& f) : f_(f), dismiss_(false) {}
	inline void dismiss() { dismiss_ = true; }
	~scoped_exit() { if (dismiss_) return; f_(); }

private:
	T f_;
	bool dismiss_;
};

#ifdef _UNICODE
#define PRIsLPTSTR      "ls"
#define PRIsLPOLESTR    "ls"
#else
#define PRIsLPTSTR      "s"
#define PRIsLPOLESTR    "ls"
#endif

const static GUID GUID_DEVCLASS_NET = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };

const static TCHAR szAdapterRegKeyPathTemplate[] = TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\%") TEXT(PRIsLPOLESTR) TEXT("\\%") TEXT(PRIsLPOLESTR) TEXT("\\Connection");
#define ADAPTER_REGKEY_PATH_MAX (_countof(TEXT("SYSTEM\\CurrentControlSet\\Control\\Network\\")) - 1 + 38 + _countof(TEXT("\\")) - 1 + 38 + _countof(TEXT("\\Connection")))


static DWORD
ExecCommand(const WCHAR* cmdline)
{
	DWORD exit_code;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD proc_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
	WCHAR* cmdline_dup = NULL;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	/* CreateProcess needs a modifiable cmdline: make a copy */
	cmdline_dup = _wcsdup(cmdline);
	if (cmdline_dup && CreateProcessW(NULL, cmdline_dup, NULL, NULL, FALSE,
		proc_flags, NULL, NULL, &si, &pi))
	{
		WaitForSingleObject(pi.hProcess, INFINITE);
		if (!GetExitCodeProcess(pi.hProcess, &exit_code))
		{
			exit_code = GetLastError();
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else
	{
		exit_code = GetLastError();
	}

	free(cmdline_dup);
	return exit_code;
}


static DWORD
check_reboot(
	_In_ HDEVINFO hDeviceInfoSet,
	_In_ PSP_DEVINFO_DATA pDeviceInfoData,
	_Inout_ LPBOOL pbRebootRequired)
{
	if (pbRebootRequired == NULL)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	SP_DEVINSTALL_PARAMS devinstall_params = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS) };
	if (!SetupDiGetDeviceInstallParams(
		hDeviceInfoSet,
		pDeviceInfoData,
		&devinstall_params))
	{
		DWORD dwResult = GetLastError();
		return dwResult;
	}

	if ((devinstall_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0)
	{
		*pbRebootRequired = TRUE;
	}

	return ERROR_SUCCESS;
}


static DWORD
get_reg_string(
	_In_ HKEY hKey,
	_In_ LPCTSTR szName,
	_Out_ LPTSTR* pszValue)
{
	if (pszValue == NULL)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	*pszValue = nullptr;

	DWORD dwValueType = REG_NONE, dwSize = 0;
	DWORD dwResult = RegQueryValueEx(
		hKey,
		szName,
		NULL,
		&dwValueType,
		NULL,
		&dwSize);
	if (dwResult != ERROR_SUCCESS)
	{
		SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
		return dwResult;
	}

	switch (dwValueType)
	{
	case REG_SZ:
	case REG_EXPAND_SZ:
	{
		/* Read value. */
		LPTSTR szValue = (LPTSTR)malloc(dwSize);
		if (szValue == NULL)
		{
			return ERROR_OUTOFMEMORY;
		}

		dwResult = RegQueryValueEx(
			hKey,
			szName,
			NULL,
			NULL,
			(LPBYTE)szValue,
			&dwSize);
		if (dwResult != ERROR_SUCCESS)
		{
			SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
			free(szValue);
			return dwResult;
		}

		if (dwValueType == REG_EXPAND_SZ)
		{
			/* Expand the environment strings. */
			DWORD
				dwSizeExp = dwSize * 2,
				dwCountExp =
#ifdef UNICODE
				dwSizeExp / sizeof(TCHAR);
#else
				dwSizeExp / sizeof(TCHAR) - 1;     /* Note: ANSI version requires one extra char. */
#endif
			LPTSTR szValueExp = (LPTSTR)malloc(dwSizeExp);
			if (szValueExp == NULL)
			{
				free(szValue);
				return ERROR_OUTOFMEMORY;
			}

			DWORD dwCountExpResult = ExpandEnvironmentStrings(
				szValue,
				szValueExp, dwCountExp
			);
			if (dwCountExpResult == 0)
			{
				free(szValueExp);
				free(szValue);
				return dwResult;
			}
			else if (dwCountExpResult <= dwCountExp)
			{
				/* The buffer was big enough. */
				free(szValue);
				*pszValue = szValueExp;
				return ERROR_SUCCESS;
			}
			else
			{
				/* Retry with a bigger buffer. */
				free(szValueExp);
#ifdef UNICODE
				dwSizeExp = dwCountExpResult * sizeof(TCHAR);
#else
				/* Note: ANSI version requires one extra char. */
				dwSizeExp = (dwCountExpResult + 1) * sizeof(TCHAR);
#endif
				dwCountExp = dwCountExpResult;
				szValueExp = (LPTSTR)malloc(dwSizeExp);
				if (szValueExp == NULL)
				{
					free(szValue);
					return ERROR_OUTOFMEMORY;
				}

				dwCountExpResult = ExpandEnvironmentStrings(
					szValue,
					szValueExp, dwCountExp);
				free(szValue);
				*pszValue = szValueExp;
				return ERROR_SUCCESS;
			}
		}
		else
		{
			*pszValue = szValue;
			return ERROR_SUCCESS;
		}
	}

	default:
		return ERROR_UNSUPPORTED_TYPE;
	}
}


static DWORD
get_net_adapter_guid(
	_In_ HDEVINFO hDeviceInfoSet,
	_In_ PSP_DEVINFO_DATA pDeviceInfoData,
	_In_ int iNumAttempts,
	_Out_ LPGUID pguidAdapter)
{
	DWORD dwResult = ERROR_BAD_ARGUMENTS;

	if (pguidAdapter == NULL || iNumAttempts < 1)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	/* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
	HKEY hKey = SetupDiOpenDevRegKey(
		hDeviceInfoSet,
		pDeviceInfoData,
		DICS_FLAG_GLOBAL,
		0,
		DIREG_DRV,
		KEY_READ);
	if (hKey == INVALID_HANDLE_VALUE)
	{
		dwResult = GetLastError();
		return dwResult;
	}

	while (iNumAttempts > 0)
	{
		/* Query the NetCfgInstanceId value. Using get_reg_string() right on might clutter the output with error messages while the registry is still being populated. */
		LPTSTR szCfgGuidString = NULL;
		dwResult = RegQueryValueEx(hKey, TEXT("NetCfgInstanceId"), NULL, NULL, NULL, NULL);
		if (dwResult != ERROR_SUCCESS)
		{
			if (dwResult == ERROR_FILE_NOT_FOUND && --iNumAttempts > 0)
			{
				/* Wait and retry. */
				Sleep(1000);
				continue;
			}

			SetLastError(dwResult); /* MSDN does not mention RegQueryValueEx() to set GetLastError(). But we do have an error code. Set last error manually. */
			break;
		}

		/* Read the NetCfgInstanceId value now. */
		dwResult = get_reg_string(
			hKey,
			TEXT("NetCfgInstanceId"),
			&szCfgGuidString);
		if (dwResult != ERROR_SUCCESS)
		{
			break;
		}

		dwResult = SUCCEEDED(CLSIDFromString(szCfgGuidString, (LPCLSID)pguidAdapter)) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
		free(szCfgGuidString);
		break;
	}

	RegCloseKey(hKey);
	return dwResult;
}


DWORD
wintun_driver::tap_create_adapter(
	_In_opt_ HWND hwndParent,
	_In_opt_ LPCTSTR szDeviceDescription,
	_In_ LPCTSTR szHwId,
	_Inout_ LPBOOL pbRebootRequired,
	_Out_ LPGUID pguidAdapter)
{
	DWORD dwResult;

	if (szHwId == NULL
		|| pbRebootRequired == NULL
		|| pguidAdapter == NULL)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	*pguidAdapter = { 0 };

	/* Create an empty device info set for network adapter device class. */
	HDEVINFO hDevInfoList = SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, hwndParent);
	if (hDevInfoList == INVALID_HANDLE_VALUE)
	{
		return GetLastError();
	}

	scoped_exit destroy_device_info([&]() mutable { SetupDiDestroyDeviceInfoList(hDevInfoList);  });

	/* Get the device class name from GUID. */
	TCHAR szClassName[MAX_CLASS_NAME_LEN];
	if (!SetupDiClassNameFromGuid(
		&GUID_DEVCLASS_NET,
		szClassName,
		_countof(szClassName),
		NULL))
	{
		return GetLastError();
	}

	/* Create a new device info element and add it to the device info set. */
	SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
	if (!SetupDiCreateDeviceInfo(
		hDevInfoList,
		szClassName,
		&GUID_DEVCLASS_NET,
		szDeviceDescription,
		hwndParent,
		DICD_GENERATE_ID,
		&devinfo_data))
	{
		return GetLastError();
	}

	/* Set a device information element as the selected member of a device information set. */
	if (!SetupDiSetSelectedDevice(
		hDevInfoList,
		&devinfo_data))
	{
		return GetLastError();
	}

	/* Set Plug&Play device hardware ID property. */
	if (!SetupDiSetDeviceRegistryProperty(
		hDevInfoList,
		&devinfo_data,
		SPDRP_HARDWAREID,
		(const BYTE*)szHwId, (DWORD)((_tcslen(szHwId) + 1) * sizeof(TCHAR))))
	{
		return GetLastError();
	}

	/* Register the device instance with the PnP Manager */
	if (!SetupDiCallClassInstaller(
		DIF_REGISTERDEVICE,
		hDevInfoList,
		&devinfo_data))
	{
		return GetLastError();
	}

	/* Install the device using DiInstallDevice()
	 * We instruct the system to use the best driver in the driver store
	 * by setting the drvinfo argument of DiInstallDevice as NULL. This
	 * assumes a driver is already installed in the driver store.
	 */
	if (!DiInstallDevice(hwndParent, hDevInfoList, &devinfo_data, NULL, 0, pbRebootRequired))
	{
		dwResult = GetLastError();
		goto cleanup_remove_device;
	}

	/* Get network adapter ID from registry. Retry for max 30sec. */
	dwResult = get_net_adapter_guid(hDevInfoList, &devinfo_data, 30, pguidAdapter);

cleanup_remove_device:
	if (dwResult != ERROR_SUCCESS)
	{
		/* The adapter was installed. But, the adapter ID was unobtainable. Clean-up. */
		SP_REMOVEDEVICE_PARAMS removedevice_params =
		{
			.ClassInstallHeader =
			{
				.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
				.InstallFunction = DIF_REMOVE,
			},
			.Scope = DI_REMOVEDEVICE_GLOBAL,
			.HwProfile = 0,
		};

		/* Set class installer parameters for DIF_REMOVE. */
		if (SetupDiSetClassInstallParams(
			hDevInfoList,
			&devinfo_data,
			&removedevice_params.ClassInstallHeader,
			sizeof(SP_REMOVEDEVICE_PARAMS)))
		{
			/* Call appropriate class installer. */
			if (SetupDiCallClassInstaller(
				DIF_REMOVE,
				hDevInfoList,
				&devinfo_data))
			{
				/* Check if a system reboot is required. */
				check_reboot(hDevInfoList, &devinfo_data, pbRebootRequired);
			}
		}
	}

	return dwResult;
}

DWORD
wintun_driver::tap_set_adapter_name(
	_In_ LPCGUID pguidAdapter,
	_In_ LPCTSTR szName,
	_In_ BOOL bSilent)
{
	DWORD dwResult;

	if (pguidAdapter == NULL || szName == NULL)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	/* Get the device class GUID as string. */
	LPOLESTR szDevClassNetId = NULL;
	[[maybe_unused]] auto rc0 = StringFromIID(GUID_DEVCLASS_NET, &szDevClassNetId);
	scoped_exit free_szDevClassNetId([&]() mutable { CoTaskMemFree(szDevClassNetId);  });

	/* Get the adapter GUID as string. */
	LPOLESTR szAdapterId = NULL;
	[[maybe_unused]] auto rc1 = StringFromIID(*pguidAdapter, &szAdapterId);
	scoped_exit free_szAdapterId([&]() mutable { CoTaskMemFree(szAdapterId);  });

	/* Render registry key path. */
	TCHAR szRegKey[ADAPTER_REGKEY_PATH_MAX];
	_stprintf_s(
		szRegKey, _countof(szRegKey),
		szAdapterRegKeyPathTemplate,
		szDevClassNetId,
		szAdapterId);

	/* Open network adapter registry key. */
	HKEY hKey = NULL;
	dwResult = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		szRegKey,
		0,
		KEY_QUERY_VALUE,
		&hKey);
	if (dwResult != ERROR_SUCCESS)
	{
		SetLastError(dwResult); /* MSDN does not mention RegOpenKeyEx() to set GetLastError(). But we do have an error code. Set last error manually. */
		return dwResult;
	}
	scoped_exit free_hKey([&]() mutable { RegCloseKey(hKey);  });

	LPTSTR szOldName = NULL;
	dwResult = get_reg_string(hKey, TEXT("Name"), &szOldName);
	if (dwResult != ERROR_SUCCESS)
	{
		SetLastError(dwResult);
		return dwResult;
	}

	/* rename adapter via netsh call */
	const TCHAR* szFmt = TEXT("netsh interface set interface name=\"%")
		TEXT(PRIsLPTSTR) TEXT("\" newname=\"%") TEXT(PRIsLPTSTR) TEXT("\"");
	size_t ncmdline = _tcslen(szFmt) + _tcslen(szOldName) + _tcslen(szName) + 1;
	WCHAR* szCmdLine = (WCHAR*)malloc(ncmdline * sizeof(TCHAR));
	_stprintf_s(szCmdLine, ncmdline, szFmt, szOldName, szName);

	free(szOldName);

	dwResult = ExecCommand(szCmdLine);
	free(szCmdLine);

	if (dwResult != ERROR_SUCCESS)
	{
		SetLastError(dwResult);
		return dwResult;
	}

	return dwResult;
}

typedef DWORD(*devop_func_t)(
	_In_ HDEVINFO hDeviceInfoSet,
	_In_ PSP_DEVINFO_DATA pDeviceInfoData,
	_Inout_ LPBOOL pbRebootRequired);


static DWORD
execute_on_first_adapter(
	_In_opt_ HWND hwndParent,
	_In_ LPCGUID pguidAdapter,
	_In_ devop_func_t funcOperation,
	_Inout_ LPBOOL pbRebootRequired)
{
	DWORD dwResult;

	if (pguidAdapter == NULL)
	{
		return ERROR_BAD_ARGUMENTS;
	}

	/* Create a list of network devices. */
	HDEVINFO hDevInfoList = SetupDiGetClassDevsEx(
		&GUID_DEVCLASS_NET,
		NULL,
		hwndParent,
		DIGCF_PRESENT,
		NULL,
		NULL,
		NULL);
	if (hDevInfoList == INVALID_HANDLE_VALUE)
	{
		dwResult = GetLastError();
		return dwResult;
	}

	scoped_exit destroy_device([&]() mutable { SetupDiDestroyDeviceInfoList(hDevInfoList);  });

	/* Retrieve information associated with a device information set. */
	SP_DEVINFO_LIST_DETAIL_DATA devinfo_list_detail_data = { .cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA) };
	if (!SetupDiGetDeviceInfoListDetail(hDevInfoList, &devinfo_list_detail_data))
	{
		dwResult = GetLastError();
		return dwResult;
	}

	/* Iterate. */
	for (DWORD dwIndex = 0;; dwIndex++)
	{
		/* Get the device from the list. */
		SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
		if (!SetupDiEnumDeviceInfo(
			hDevInfoList,
			dwIndex,
			&devinfo_data))
		{
			if (GetLastError() == ERROR_NO_MORE_ITEMS)
			{
				/*
								LPOLESTR szAdapterId = NULL;
								StringFromIID((REFIID)pguidAdapter, &szAdapterId);
								msg(M_NONFATAL, "%s: Adapter %" PRIsLPOLESTR " not found", __FUNCTION__, szAdapterId);
								CoTaskMemFree(szAdapterId);
				*/
				dwResult = ERROR_FILE_NOT_FOUND;
				return dwResult;
			}
			else
			{
				/* Something is wrong with this device. Skip it. */
				continue;
			}
		}

		/* Get adapter GUID. */
		GUID guidAdapter;
		dwResult = get_net_adapter_guid(hDevInfoList, &devinfo_data, 1, &guidAdapter);
		if (dwResult != ERROR_SUCCESS)
		{
			/* Something is wrong with this device. Skip it. */
			continue;
		}

		/* Compare GUIDs. */
		if (memcmp(pguidAdapter, &guidAdapter, sizeof(GUID)) == 0)
		{
			dwResult = funcOperation(hDevInfoList, &devinfo_data, pbRebootRequired);
			break;
		}
	}

	return dwResult;
}


static DWORD
delete_device(
	_In_ HDEVINFO hDeviceInfoSet,
	_In_ PSP_DEVINFO_DATA pDeviceInfoData,
	_Inout_ LPBOOL pbRebootRequired)
{
	SP_REMOVEDEVICE_PARAMS params =
	{
		.ClassInstallHeader =
		{
			.cbSize = sizeof(SP_CLASSINSTALL_HEADER),
			.InstallFunction = DIF_REMOVE,
		},
		.Scope = DI_REMOVEDEVICE_GLOBAL,
		.HwProfile = 0,
	};

	/* Set class installer parameters for DIF_REMOVE. */
	if (!SetupDiSetClassInstallParams(
		hDeviceInfoSet,
		pDeviceInfoData,
		&params.ClassInstallHeader,
		sizeof(SP_REMOVEDEVICE_PARAMS)))
	{
		DWORD dwResult = GetLastError();
		return dwResult;
	}

	/* Call appropriate class installer. */
	if (!SetupDiCallClassInstaller(
		DIF_REMOVE,
		hDeviceInfoSet,
		pDeviceInfoData))
	{
		DWORD dwResult = GetLastError();
		return dwResult;
	}

	/* Check if a system reboot is required. */
	check_reboot(hDeviceInfoSet, pDeviceInfoData, pbRebootRequired);
	return ERROR_SUCCESS;
}


DWORD
wintun_driver::tap_delete_adapter(
	_In_opt_ HWND hwndParent,
	_In_ LPCGUID pguidAdapter,
	_Inout_ LPBOOL pbRebootRequired)
{
	return execute_on_first_adapter(hwndParent, pguidAdapter, delete_device, pbRebootRequired);
}
