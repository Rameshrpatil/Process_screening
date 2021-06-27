using namespace std;

#include<sys/types.h>
#include<sys/stat.h>
#include<iostream>
#include<string.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<stdio.h>
#include<io.h>
#include<assert.h>
#include<stdlib.h>
 
typedef struct Logfile
{
	char ProcessName[100];
	unsigned int pid;
	unsigned int ppid;
	unsigned int thread_cnt;
}LOGFILE;

class ThreadInfo
{
private:
	DWORD PID;
	HANDLE hThreadSnap;
	THREADENTRY32 te32;
public:
	ThreadInfo(DWORD);
	BOOL ThreadsDisplay();
};

ThreadInfo::ThreadInfo(DWORD no)
{
	PID = no;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);

	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Unable to create snapshot of current thread pool" << endl;
		return;
	}

	te32.dwSize = sizeof(THREADENTRY32);
}

BOOL ThreadInfo::ThreadsDisplay()
{
	if (!Thread32First(hThreadSnap, &te32))
	{
		cout << "Error In Getting the First Thread" << endl;
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	cout << endl << "THREAD OF THIS PROCESS :" << endl;
	do
	{
		if (te32.th32OwnerProcessID == PID)
		{
			cout << "\tTHREAD ID : " << te32.th32ThreadID << endl;
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	return TRUE;
}

class DLLInfo
{
private:
	DWORD PID;
	MODULEENTRY32 me32;
	HANDLE hProcessSnap;
public:
	DLLInfo(DWORD);
	BOOL DependentDLLDisplay();

};

DLLInfo::DLLInfo(DWORD ino)
{
	PID = ino;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "Error: Unable to create the snapshot of current thread pool" << endl;
		return;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
}

BOOL DLLInfo::DependentDLLDisplay()
{
	char arr[200];
	if (!Module32First(hProcessSnap, &me32))
	{
		cout << "Failed to get DLL information" << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	cout << "Dependent DLL of this Process" << endl;
	do
	{
		wcstombs_s(NULL, arr, 200, me32.szModule, 200);
		cout << arr << endl;
	} while (Module32Next(hProcessSnap, &me32));
	CloseHandle(hProcessSnap);
	return TRUE;
}

class ProcessInfo
{
private:
	DWORD PID;
	DLLInfo* pdobj;
	ThreadInfo* ptobj;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
public:
	ProcessInfo();
	BOOL ProcessDisplay(const char*);
	BOOL ProcessLog();
	BOOL ReadLog(DWORD, DWORD, DWORD, DWORD);
	BOOL ProcessSearch(char*);
	BOOL KillProcess(char*);
};

ProcessInfo::ProcessInfo()
{
	ptobj = NULL;
	pdobj = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout << "ERROR : Unable to create the snapshot of runniong process" << endl;
		return;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
}

BOOL ProcessInfo::ProcessLog()
{
	const char* month[] = { "jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec" };
	char FileName[50], arr[200];
	int ret = 0, fd=0, count = 0;
	SYSTEMTIME STime;
	LOGFILE fobj;
	FILE* fp;

	GetLocalTime(&STime);

	sprintf_s(FileName, "D://process_screening/RamLog %02d_%02d_%02d%s.txt", STime.wHour, STime.wMinute, STime.wDay, month[STime.wMonth - 1]);
	fp = fopen(FileName, "wb");
	if (fp == NULL)
	{
		cout << "Unable to create log file " << endl;
		return FALSE;
	}
	else
	{
		cout << "log file  successfully created as : " << FileName << endl;
		cout << "Time of Log File creation is --> " << STime.wHour << ":" << STime.wMinute << ":" << STime.wSecond << ":" << STime.wDay << ":" << month[STime.wMonth - 1] << endl;
	}

	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "ERROR : error in finding the first Process " << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do
	{
		wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		strcpy_s(fobj.ProcessName, arr);
		fobj.pid = pe32.th32ProcessID;
		fobj.ppid = pe32.th32ParentProcessID;
		fobj.thread_cnt = pe32.cntThreads;
		fwrite(&fobj, sizeof(fobj), 1, fp);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	fclose(fp);
	return TRUE;
}


BOOL ProcessInfo::ProcessDisplay(const char* Option)
{
	char arr[200];
	if (!Process32First(hProcessSnap, &pe32))
	{
		cout << "ERROR :In Finding the First Process" << endl;
		CloseHandle(hProcessSnap);
	    return  FALSE;
	}

	do
	{

		cout << endl << "*******************************************************************************";
		wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		cout << endl << "PROCESS NAME:" << arr;
		cout << endl << "PID:" << pe32.th32ProcessID;
		cout << endl << "PPID:" << pe32.th32ParentProcessID;
		cout << endl << "Number of Threads:" << pe32.cntThreads;

		if ((_stricmp(Option, "-a") == 0) ||
			(_stricmp(Option, "-d") == 0) ||
			(_stricmp(Option, "-t") == 0))
		{
			if ((_stricmp(Option, "-t") == 0) || (_stricmp(Option, "-a") == 0))
			{
				ptobj = new ThreadInfo(pe32.th32ProcessID);
				ptobj->ThreadsDisplay();
				delete ptobj;
			}
			if ((_stricmp(Option, "-d") == 0) || (_stricmp(Option, "-a") == 0))
			{
				pdobj = new DLLInfo(pe32.th32ProcessID);
				pdobj->DependentDLLDisplay();
				delete pdobj;
			}
		}
		cout << endl << "****************************************************************************";
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return TRUE;
}

BOOL ProcessInfo::ReadLog(DWORD hr, DWORD min, DWORD date, DWORD month)
{
	char FileName[50];
	const char* montharr[] = { "jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec" };
	int ret = 0, count = 0;
	LOGFILE fobj;
	FILE* fp;
	sprintf_s(FileName, "D://process_screening/RamLog %02d_%02d_%02d%s.txt", hr, min, date, montharr[month - 1]);
	fp = fopen(FileName, "rb");
	if (fp == NULL)
	{
		cout << "ERROR: Unable Open log File named as: " << FileName << endl;
		return FALSE;
	}
	while ((ret = fread(&fobj, 1, sizeof(fobj), fp)) != 0)
	{
		cout << "************************************************************************************" << endl;
		cout << "Process NAME :" << fobj.ProcessName << endl;
		cout << "PID of Current Process :" << fobj.pid << endl;
		cout << "Parent Process ID of Current Proccess :" << fobj.ppid << endl;
		cout << "Thread count of Process :" << fobj.thread_cnt << endl;
	}
	return TRUE;
}

BOOL ProcessInfo::ProcessSearch(char* name)
{
	char arr[200];
	BOOL Flag = FALSE;
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		if (_stricmp(arr, name) == 0)
		{
			cout << endl << "Process NAME :" << arr;
			cout << endl << "PID :" << pe32.th32ProcessID;
			cout << endl << "PPID :" << pe32.th32ParentProcessID;
			cout << endl << "Number of Threads :" << pe32.cntThreads;
			Flag = TRUE;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return Flag;
}

BOOL ProcessInfo::KillProcess(char* name)
{
	char arr[200];
	int pid = -1;
	BOOL bret;
	HANDLE hpr;
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		if (_stricmp(arr, name) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	if (pid == -1)
	{
		cout << "ERROR : There is no such process" << endl;
		return FALSE;
	}
	hpr = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	if (hpr == NULL)
	{
		cout << "ERROR   :  There is no access to tirminate" << endl;
		return FALSE;
	}
	bret = TerminateProcess(hpr, 0);
	if (bret == FALSE)
	{
		cout << "error: Unable to terminate Process" << endl;
		return FALSE;
	}

}

BOOL HadwareInfo()
{
	SYSTEM_INFO sysinfor;
	GetSystemInfo(&sysinfor);
	cout << "OEM ID :" << sysinfor.dwOemId << endl;
	cout << "Number of Processors :" << sysinfor.dwNumberOfProcessors << endl;
	cout << "Page size :" << sysinfor.dwPageSize << endl;
	cout << "Processor Type :" << sysinfor.dwProcessorType << endl;
	cout << "Minimum application address :" << sysinfor.lpMinimumApplicationAddress << endl;
	cout << "Maximum application address :" << sysinfor.lpMaximumApplicationAddress << endl;
	cout << "Active Processor mask :" << sysinfor.dwActiveProcessorMask << endl;
	return TRUE;
}

void DisplayHelp()
{
	cout << "Help regarding commands" << endl;
	cout << "ps :Display all information of process" << endl;
	cout << "ps-t :Display all information about threads" << endl;
	cout << "ps-d :Display all information about DLL" << endl;
	cout << "cls :Clear the contents on console" << endl;
	cout << "log :Creates log of the current running Process on D drive in Process_screening folder" << endl;
	cout << "readlog :Display the information from specified log file" << endl;
	cout << " sysinfo :Display the current hardware configuration " << endl;
	cout << "search : Search and display information of specific running process " << endl;
	cout << "exit : Terminate process_screening" << endl;
}


int main(int argc, char* argv[])
{
	BOOL bret = FALSE;
	char* ptr = NULL;
	ProcessInfo* ppobj = NULL;
	char command[4][80], str[80];
	int count =0, min =0, date =0 , month =0, hr =0;

	while(1)
	{
		fflush(stdin);
		strcpy_s(str, _countof(str), "");
		cout << endl << "Ram's Process_screening -->";
		fgets(str, 80, stdin);
		count = sscanf(str, "%s %s %s %s", command[0], command[1], command[2], command[3]);

		if (count == 1)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay("-a");
				if (bret == FALSE)
				{
					cout << "ERROR :Unable to display Process" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "log") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessLog();
				if (bret == FALSE)
				{
					cout << "ERROR : unable to create log file" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "sysinfo") == 0)
			{
				bret = HadwareInfo();
				if (bret == FALSE)
				{
					cout << "ERROR : Unable to get Hardware information" << endl;
				}
				//cout << "Hardware Information of current System is :" << endl;
			}
			else if (_stricmp(command[0], "readlog") == 0)
			{
				ProcessInfo* ppobj;
				ppobj = new ProcessInfo();
				cout << "Enter log file details as :" << endl;

				cout << "Hour: ";
				cin >> hr;

				cout << endl << "Minute:";
				cin >> min;

				cout << endl << "date :";
				cin >> date;

				cout << endl << "Month :";
				cin >> month;

				bret = ppobj->ReadLog(hr, min, date, month);
				if (bret == FALSE)
				{
					cout << "ERROR :Unable to read the specified log file" << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "clear") == 0)
			{
				system("cls");
				continue;
			}
			else if (_stricmp(command[0], "help") == 0)
			{
				DisplayHelp();
				continue;
			}
			else if (_stricmp(command[0], "exit") == 0)
			{
				cout << endl << "terminateing the Process_screening Program " << endl;
				break;
			}
			else
			{
				cout << "ERROR : command not found!!!" << endl;
				continue;
			}
		}
		else if (count == 2)
		{
			if (_stricmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay(command[1]);
				if (bret == FALSE)
				{
					cout << "ERROR :Unable to displayprocess information " << endl;
				}
				delete ppobj;
			}
			else if (_stricmp(command[0], "search") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessSearch(command[1]);
				if (bret == FALSE)
				{
					cout << "ERROR : There is no such process" << endl;
				}
				delete ppobj;
				continue;
			}
			else if (_stricmp(command[0], "kill") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->KillProcess(command[1]);
				if (bret == FALSE)
				{
					cout << "ERROR : threre is no such process" << endl;
				}
				else
				{
					cout << command[1] << "Terminated Sucessfully" << endl;
				}
				delete ppobj;
				continue;
			}
		}
		else
		{
			cout << endl << "ERROR :Command not found !!!" << endl;
			continue;
		}
	}
	return 0;
}
				
			
		
	

	
