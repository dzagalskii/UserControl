#include "stdafx.h"
#include "DLLFunctions.h"
#include "UserControl.h"

//структура с привилегиями
struct Privileges
{
    LPWSTR PrivilegeStr;//привилегия
    LPWSTR DescriptionStr;//описание привилегии
};

//массив структур с привилегиями
Privileges _privileges__lpwstr_array[] =
{
    {   (LPWSTR)L"SeAssignPrimaryTokenPrivilege",
        (LPWSTR)L"Required to assign the primary token of a process. User Right : Replace a process - level token."},

    {   (LPWSTR)L"SeAuditPrivilege",
        (LPWSTR)L"Required to generate audit - log entries.Give this privilege to secure servers. User Right : Generate security audits."},

    {   (LPWSTR)L"SeBackupPrivilege",
        (LPWSTR)L"User Right : Back up files and directories."},

    {   (LPWSTR)L"SeChangeNotifyPrivilege",
        (LPWSTR)L"User Right : Bypass traverse checking."},

    {   (LPWSTR)L"SeCreateGlobalPrivilege",
        (LPWSTR)L"User Right : Create global objects."},

    {   (LPWSTR)L"SeCreatePagefilePrivilege",
        (LPWSTR)L"Required to create a paging file. User Right : Create a pagefile."},

    {   (LPWSTR)L"SeCreatePermanentPrivilege",
        (LPWSTR)L"Required to create a permanent object. User Right : Create permanent shared objects."},

    {   (LPWSTR)L"SeCreateSymbolicLinkPrivilege",
        (LPWSTR)L"Required to create a symbolic link. User Right : Create symbolic links."},

    {   (LPWSTR)L"SeCreateTokenPrivilege",
        (LPWSTR)L"Required to create a primary token. User Right : Create a token object."},

    {   (LPWSTR)L"SeDebugPrivilege",
        (LPWSTR)L"Required to debug and adjust the memory of a process owned by another account. User Right : Debug programs." },

    {   (LPWSTR)L"SeEnableDelegationPrivilege",
        (LPWSTR)L"Required to mark user and computer accounts as trusted for delegation. User Right : Enable computer and user accounts to be trusted for delegation." },

    {   (LPWSTR)L"SeImpersonatePrivilege",
        (LPWSTR)L"Required to impersonate. User Right : Impersonate a client after authentication." },

    {   (LPWSTR)L"SeIncreaseBasePriorityPrivilege",
        (LPWSTR)L"Required to increase the base priority of a process. User Right : Increase scheduling priority." },

    {   (LPWSTR)L"SeIncreaseQuotaPrivilege",
        (LPWSTR)L"Required to increase the quota assigned to a process. User Right : Adjust memory quotas for a process." },

    {   (LPWSTR)L"SeIncreaseWorkingSetPrivilege",
        (LPWSTR)L"Required to allocate more memory for applications that run in the context of users. User Right : Increase a process working set." },

    {   (LPWSTR)L"SeLoadDriverPrivilege",
        (LPWSTR)L"Required to load or unload a device driver. User Right : Load and unload device drivers." },

    {   (LPWSTR)L"SeLockMemoryPrivilege",
        (LPWSTR)L"Required to lock physical pages in memory. User Right : Lock pages in memory." },

    {   (LPWSTR)L"SeMachineAccountPrivilege",
        (LPWSTR)L"Required to create a computer account. User Right : Add workstations to domain." },

    {   (LPWSTR)L"SeManageVolumePrivilege",
        (LPWSTR)L"Required to enable volume management privileges. User Right : Manage the files on a volume." },

    {   (LPWSTR)L"SeProfileSingleProcessPrivilege",
        (LPWSTR)L"Required to gather profiling information for a single process. User Right : Profile single process." },

    {   (LPWSTR)L"SeRelabelPrivilege",
        (LPWSTR)L"Required to modify the mandatory integrity level of an object. User Right : Modify an object label." },

    {   (LPWSTR)L"SeRemoteShutdownPrivilege",
        (LPWSTR)L"Required to shut down a system using a network request. User Right : Force shutdown from a remote system." },

    {   (LPWSTR)L"SeRestorePrivilege",
        (LPWSTR)L"User Right : Restore files and directories." },

    {   (LPWSTR)L"SeSecurityPrivilege",
        (LPWSTR)L"User Right : Manage auditing and security log." },

    {   (LPWSTR)L"SeShutdownPrivilege",
        (LPWSTR)L"Required to shut down a local system. User Right : Shut down the system." },

    {   (LPWSTR)L"SeSyncAgentPrivilege",
        (LPWSTR)L"User Right : Synchronize directory service data." },

    {   (LPWSTR)L"SeSystemEnvironmentPrivilege",
        (LPWSTR)L"Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information. User Right : Modify firmware environment values." },

    {   (LPWSTR)L"SeSystemProfilePrivilege",
        (LPWSTR)L"Required to gather profiling information for the entire system. User Right : Profile system performance." },

    {   (LPWSTR)L"SeSystemtimePrivilege",
        (LPWSTR)L"Required to modify the system time. User Right : Change the system time." },

    {   (LPWSTR)L"SeTakeOwnershipPrivilege",
        (LPWSTR)L"User Right : Take ownership of files or other objects." },

    {   (LPWSTR)L"SeTcbPrivilege",
        (LPWSTR)L"User Right : Act as part of the operating system." },

    {   (LPWSTR)L"SeTimeZonePrivilege",
        (LPWSTR)L"Required to adjust the time zone associated with the computer's internal clock. User Right : Change the time zone." },

    {   (LPWSTR)L"SeTrustedCredManAccessPrivilege",
        (LPWSTR)L"Required to access Credential Manager as a trusted caller. User Right : Access Credential Manager as a trusted caller." },

    {   (LPWSTR)L"SeUndockPrivilege",
        (LPWSTR)L"Required to undock a laptop. User Right : Remove computer from docking station." },

    {   (LPWSTR)L"SeUnsolicitedInputPrivilege",
        (LPWSTR)L"Required to read unsolicited input from a terminal device. User Right : Not applicable." }
    
};

//просто перечисление привилегий с индексами
void List_Privileges(void)
{
    for (size_t i = 0; i < sizeof(_privileges__lpwstr_array)/sizeof(Privileges); i++)
    {
        wprintf(L"# %d: %s\n%s\n", i, _privileges__lpwstr_array[i].PrivilegeStr, _privileges__lpwstr_array[i].DescriptionStr);
    }
}

//добавить пользователя
int Add_User(LPWSTR lpszUser, LPWSTR lpszPassword)
{
    USER_INFO_1               user_info;
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    //настройка сруктуры USER_INFO
    user_info.usri1_name = lpszUser;
    user_info.usri1_password = lpszPassword;
    user_info.usri1_priv = USER_PRIV_USER;
    user_info.usri1_home_dir = (LPWSTR)TEXT("");
    user_info.usri1_comment = (LPWSTR)TEXT("Sample User");
    user_info.usri1_flags = UF_SCRIPT;
    user_info.usri1_script_path = (LPWSTR)TEXT("");

    //добавляем учетную запись пользователя
    //и назначаем пароль и уровень привилегий
    nStatus = NetUserAddPtr(NULL,         
        1,                    
        (LPBYTE)&user_info,  
        &parm_err);          

    //в зависимости от возвращаемого значения
    //выводим то или иное сообщение об
    //успехе или неудаче
    switch (nStatus)
    {
    case 0:
        printf("# User successfully created.\n");
        break;
    case NERR_UserExists:
        printf("# User already exists.\n");
        nStatus = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("# Invalid parameter error adding user; parameter index = %d\n", parm_err);
        return(nStatus);
    default:
        printf("# Error adding user: %d\n", nStatus);
        return(nStatus);
    }
    return(nStatus);
}

//удалить пользователя
int Delete_User(LPWSTR lpszUser)
{
    //удаляет учетную запись пользователя
    //из системы
    return NetUserDelPtr(NULL, lpszUser);
}

//установить привилегию в указанном маркере доступа
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    //извлекаем локальный уникальный идентификатор(LUID), 
    //используемый в указанной системе для локального представления указанного имени привилегии
    if (!LookupPrivilegeValue(
        NULL,            
        lpszPrivilege,   
        &luid))       
    {
        //при неудаче выводим ошибку
        printf("# LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    //если привелегия включена, отключим
    //если привелегия выключена, включим
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }
    
    //включаем или отключаем привилегию в указанном маркере доступа
    if (!AdjustTokenPrivilegesPtr(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        //при неудаче выводим ошибку
        printf("# AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }
    //если токен не имеет такой привилегии
    //выводим ошибку об этом
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("# The token does not have the specified privilege. \n");
        return FALSE;
    }
    return TRUE;
}

//LPCWSTR -> PLSA_UNICODE_STRING
bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
    DWORD dwLen = 0;
    if (NULL == pLsaString)
        return FALSE;
    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        //если строчка слишком велика
        if (dwLen > 0x7ffe)
            return FALSE;
    }
    //сохраняем строку
    pLsaString->Buffer = (WCHAR *)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);
    return TRUE;
}

//установить привилегии для пользователя(группы)
int Set_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;
    NET_API_STATUS nStatus = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    //получаем идентификатор безопасности (SID) 
    //для учетной записи и имя домена, в котором была найдена
    //изменяемая сейчас учетная запись
    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"can't LookupAccountName\n");
        return 0;
    }

    //получим дескриптор объекта Policy (LSA_HANDLE)
    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"err\n");
        return 0;
    }

    //назначаем учетной записи один или несколько привилегий
    //если учетная запись не существует, LsaAddAccountRights создаст ее
    LSA_UNICODE_STRING UserRights;
    InitLsaString(&UserRights, _privileges__lpwstr_array[_privilege_index].PrivilegeStr);
    nStatus= LsaAddAccountRightsPtr(policy_handle, userSID, &UserRights, 1);
    DWORD err = LsaNtStatusToWinErrorPtr(nStatus);
    return 0;
}

//удалить привилегию пользователя(группы)
int Clear_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;
    NET_API_STATUS            nStatus = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    //получаем идентификатор безопасности (SID) 
    //для учетной записи и имя домена, в котором была найдена
    //изменяемая сейчас учетная запись
    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"# can't LookupAccountName\n");
        return 0;
    }

    //получим дескриптор объекта Policy (LSA_HANDLE)
    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"# can't GetPolicyHandle!\n");
        return 0;
    }
   
    //удаляем одну привилегию из учетной записи 
    //при указании привилегий, не принадлежащих учетной записи, функция игнорирует их
    LSA_UNICODE_STRING UserRights;
    InitLsaString(&UserRights, _privileges__lpwstr_array[_privilege_index].PrivilegeStr);
    LsaRemoveAccountRightsPtr(policy_handle, userSID, FALSE, &UserRights, 1);
    DWORD err = LsaNtStatusToWinErrorPtr(nStatus);
    return 0;
}

//удалить все привилегии пользователя(группы)
int Clear_All_User_Privileges(LPWSTR lpszUser)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    //получаем идентификатор безопасности (SID) 
    //для учетной записи и имя домена, в котором была найдена
    //изменяемая сейчас учетная запись
    if (!LookupAccountNamePtr(NULL, (LPWSTR)lpszUser, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"# can't LookupAccountName\n");
        return 0;
    }

    //получим дескриптор объекта Policy (LSA_HANDLE)
    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"# can't GetPolicyHandle\n");
        return 0;
    }
    //удаляем все привилегии из учетной записи
    LsaRemoveAccountRightsPtr(policy_handle, userSID, TRUE, NULL, 0);
    return 0;
}

//добавить пользователя в группу
int Assign_User_To_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup)
{
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    //заполняем структуру члена группы LOCALGROUP_MEMBERS_INFO_3
    localgroup_members.lgrmi3_domainandname = lpszUser;

    //добавляем членство учетной записи
    //пользователя локальной группе
    //если учетная запись уже член группы, ничего не произойдет
    nStatus = NetLocalGroupAddMembersPtr(NULL, 
        lpszLocalGroup,        
        3,                           
        (LPBYTE)&localgroup_members, 
        1);                          

    //в зависимости от возвращаемого значения
    //выводим то или иное сообщение об
    //успехе или неудаче
    switch (nStatus)
    {
    case 0:
        printf("User successfully added to local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("User already in local group.\n");
        nStatus = 0;
        break;
    default:
        printf("Error adding user to local group: %d\n", nStatus);
        break;
    }
    return(nStatus);
}

//удалить пользователя из группы
int Exclude_User_From_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup)
{
    LOCALGROUP_MEMBERS_INFO_3 localgroup_members;
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;

    //заполняем структуру члена группы LOCALGROUP_MEMBERS_INFO_3
    localgroup_members.lgrmi3_domainandname = lpszUser;

    //удаляем учетную запись пользователя из локальной группы
    nStatus = NetLocalGroupDelMembersPtr(NULL,      
        lpszLocalGroup,               
        3,                           
        (LPBYTE)&localgroup_members,
        1);                         

    //в зависимости от возвращаемого значения
    //выводим то или иное сообщение об
    //успехе или неудаче
    switch (nStatus)
    {
    case 0:
        printf("User successfully removed from local group.\n");
        break;
    case ERROR_MEMBER_IN_ALIAS:
        printf("No such user in local group.\n");
        nStatus = 0;
        break;
    default:
        printf("Error removing user from local group: %d\n", nStatus);
        break;
    }
    return(nStatus);
}

//добавить группу
int Add_Group(LPWSTR lpszLocalGroup)
{
    NET_API_STATUS            nStatus = 0;
    DWORD                     parm_err = 0;
    LOCALGROUP_INFO_1         localgroup_info;

    //заполнение структуры LOCALGROUP_INFO_1
    localgroup_info.lgrpi1_name = lpszLocalGroup;
    localgroup_info.lgrpi1_comment = (LPWSTR)TEXT("Sample local group.");

    //создаем локальную группу в базе данных безопасности
    nStatus = NetLocalGroupAddPtr(NULL, 1, (LPBYTE)&localgroup_info, &parm_err);

    //в зависимости от возвращаемого значения
    //выводим то или иное сообщение об
    //успехе или неудаче
    switch (nStatus)
    {
    case 0:
        printf("# Local group successfully created.\n");
        break;
    case ERROR_ALIAS_EXISTS:
        printf("# Local group already exists.\n");
        nStatus = 0;
        break;
    case ERROR_INVALID_PARAMETER:
        printf("# Invalid parameter error adding local group; parameter index = %d - %d\n", nStatus, parm_err);
        return(nStatus);
    default:
        printf("# Error adding local group: %d\n", nStatus);
        return(nStatus);
    }
    return(nStatus);
}

//удалить группу
int Delete_Group(LPWSTR lpszLocalGroup)
{
    //удаляем локальную группы и всех ее участников из базы данных безопасности
    return NetLocalGroupDelPtr(NULL, lpszLocalGroup);
}

//распечатать привилегии пользователя или группы
void printPrivileges(LPWSTR lpszUser)
{
    DWORD dwUserBuf = 256;
    ULONG CountOfRights = 0;

    BYTE bySidBuffer[1024];
    TCHAR  lpDomainName[256];
    SID_NAME_USE typeOfSid;
    PLSA_UNICODE_STRING pUserRights;
    PSID lpSid = (PSID)bySidBuffer;

    DWORD dwSidLength = sizeof(bySidBuffer);
    DWORD dwLengthOfDomainName = sizeof(lpDomainName);

    //получаем идентификатор безопасности (SID) 
    //для учетной записи и имя домена, в котором была найдена
    //изменяемая сейчас учетная запись
    if (!LookupAccountName(NULL, lpszUser, lpSid, &dwSidLength,
        (LPTSTR)lpDomainName, &dwLengthOfDomainName, &typeOfSid)) {
        fprintf(stderr, "Lookup account name failed: %d\n", GetLastError());
        return;
    }

    //получим дескриптор объекта Policy (LSA_HANDLE)
    LSA_HANDLE pHandle = GetPolicyHandle();
    if (!pHandle) {

        fprintf(stderr, "Get policy handle failed: %d\n", GetLastError());
        return;
    }

    //перечисляем привилегии, назначенные учетной записи
    LsaEnumerateAccountRights(pHandle, lpSid, &pUserRights, &CountOfRights);
    if (CountOfRights != 0) {
        wprintf(L"\tPrivileges:\n");
        for (size_t i = 0; i < CountOfRights; i++)
            wprintf(L"\t\t   %s\n", pUserRights[i].Buffer);
    }
    LsaClose(pHandle);
    LsaFreeMemory(pUserRights);
}

//получить дескриптор объекта Policy (LSA_HANDLE)
LSA_HANDLE GetPolicyHandle(void)
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    //обнулим атрибуты объекта
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    //получим дескриптор объекта Policy
    ntsResult = LsaOpenPolicyPtr(
        NULL,    //имя целевой системы
        &ObjectAttributes, //атрибуты объекта
        POLICY_ALL_ACCESS | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, //желаемые права доступа
        &lsahPolicyHandle  //собсна сам дескриптор
    );

    //распечатать ошибку, если ошибка
    if (ntsResult != STATUS_SUCCESS)
    {
        wprintf(L"# OpenPolicy returned %lu\n", LsaNtStatusToWinErrorPtr(ntsResult));
        return NULL;
    }
    return lsahPolicyHandle;
}

//перечислить привилегии 
void Enumerate_Privileges(LPTSTR _user_name)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;
    LSA_HANDLE policy_handle = NULL;
    PLSA_UNICODE_STRING pp_user_rights;
    ULONG count_of_rights = 0;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    //получим SID для учетной записи
    //если не вышло, выведем ошибку
    if (!LookupAccountNamePtr(NULL, (LPWSTR)_user_name, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"# can't LookupAccountName\n");
        return;
    }

    //получим дескриптор объекта Policy
    //если не вышло, выведем ошибку
    policy_handle = GetPolicyHandle();
    if (!policy_handle)
    {
        wprintf(L"# can't GetPolicyHandle\n");
        return;
    }

    //получим прака учетной записи
    //распечатаем их
    LsaEnumerateAccountRightsPtr(policy_handle, userSID, &pp_user_rights, &count_of_rights);
    wprintf(L"#\t Privileges:\n");
    for (size_t i = 0; i < count_of_rights; i++)
    {
        wprintf(L"#\t\t %s\n", pp_user_rights[i].Buffer);
    }
    return;
}

//получить SID пользователя по имени
void Get_User_Sid(LPTSTR _user_name)
{
    DWORD dwUserBuf = 256;
    PSID userSID = NULL;
    DWORD dwSID, dwDomainNameSize = 0;
    BYTE bySidBuffer[1024];
    LPTSTR chSID = NULL;
    TCHAR  chDomainName[256];
    SID_NAME_USE snu;

    userSID = (PSID)bySidBuffer;
    dwSID = sizeof(bySidBuffer);
    dwDomainNameSize = sizeof(chDomainName);

    //получим SID для учетной записи
    //если не вышло, выведем ошибку
    if (!LookupAccountNamePtr(NULL, (LPWSTR)_user_name, (PSID)userSID, (LPDWORD)&dwSID, (LPTSTR)chDomainName, (LPDWORD)&dwDomainNameSize, (PSID_NAME_USE)&snu))
    {
        wprintf(L"# can't LookupAccountName\n");
    }

    //распечатываем
    ConvertSidToStringSidPtr(userSID, &chSID);
    wprintf(L"#\t SID:\n#\t\t%s\n", chSID);
    LocalFree((HLOCAL)chSID);
    return;
}

//перечислить пользователей
void Enumerate_Users(LPTSTR _server_name)
{
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = _server_name;

    //пока есть записи о пользователях,
    //получаем их
    do
    {
        //получаем информацию о всех
        //учетных записях в системе
        nStatus = NetUserEnumPtr((LPCWSTR)pszServerName,
            dwLevel,
            FILTER_NORMAL_ACCOUNT, //глобальные пользователи
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);
        //если удалось
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                //пройдем по полученному 
                //списку аккаунтов
                for (i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);

                    if (pTmpBuf == NULL)
                    {
                        fprintf(stderr, "An access violation has occurred\n");
                        break;
                    }

                    //распечатываем имя, сид, группы, привилегии
                    wprintf(L"\n# user name: %s\n", pTmpBuf->usri0_name);
                    Get_User_Sid(pTmpBuf->usri0_name);
                    Enumerate_Groups(pTmpBuf->usri0_name);
                    Enumerate_Privileges(pTmpBuf->usri0_name);
                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        //иначе распечатаем ошибку
        else
        {
            fprintf(stderr, "A system error has occurred: %d\n", nStatus);
        }
        //освобождаем выделенную память, если выделялась
        if (pBuf != NULL)
        {
            NetApiBufferFreePtr(pBuf);
            pBuf = NULL;
        }
    } while (nStatus == ERROR_MORE_DATA);
    //освобождаем выделенную память, если выделялась
    if (pBuf != NULL)
    {
        NetApiBufferFreePtr(pBuf);
    }
    return;
}

//перечислить группы указанного пользователя
void Enumerate_Groups(LPWSTR _user_name)
{
    LPBYTE buffer;
    DWORD entries;
    DWORD total_entries;
    LOCALGROUP_USERS_INFO_0* groups;

    //извлекаем список локальных групп, 
    //к которым принадлежит указанный пользователь
    NetUserGetLocalGroupsPtr(NULL, _user_name, 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    groups = (LOCALGROUP_USERS_INFO_0*)buffer;
    //распечатываем
    printf("#\t local groups: \n");
    for (int i = 0; i < entries; i++)
    {
        printf("#\t\t%S\n", groups[i].lgrui0_name);
    }
    NetApiBufferFreePtr(buffer);

    // извлекает список глобальных групп, 
    //к которым принадлежит указанный пользователь.
    NetUserGetGroupsPtr(NULL, _user_name, 0, &buffer, MAX_PREFERRED_LENGTH, &entries, &total_entries);
    GROUP_USERS_INFO_0* ggroups = (GROUP_USERS_INFO_0*)buffer;
    //распечатываем
    printf("#\t global groups: \n");
    for (int i = 0; i < entries; i++)
    {
        printf("#\t\t%S\n", ggroups[i].grui0_name);
    }
    NetApiBufferFreePtr(buffer);
    return;
}

//перечислить все группы в системе
void Get_Groups_Enum(void)
{
    LPGROUP_INFO_1 pBuf = NULL;
    LPGROUP_INFO_1 pTmpBuf;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    PDWORD_PTR dwResumeHandle = 0;
    NET_API_STATUS status;

    TCHAR compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD nSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerName(compName, &nSize);

    wprintf(L"# Local groups on %s: \n", compName);

    //пока есть записи о группах,
    //получаем их
    do
    {
        //получаем информацию о всех
        //группах, присутствующих в системе
        status = NetLocalGroupEnumPtr(NULL,
            1,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &dwEntriesRead,
            &dwTotalEntries,
            dwResumeHandle);
        //если успешно
        if ((status == NERR_Success) || (status == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                //распечатываем группы из списка
                for (DWORD i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);
                    if (pTmpBuf == NULL)
                    {
                        fprintf(stderr, "An access violation has occurred\n");
                        break;
                    }
                    //распечатываем имя
                    wprintf(L"# %s\n", pTmpBuf->grpi1_name);

                    DWORD sidLength = 0;
                    DWORD sidLengthDomain = 0;
                    SID_NAME_USE sidType;
                    LPTSTR sStringSid = NULL;

                    //получаем SID
                    LookupAccountNamePtr(NULL, pTmpBuf->grpi1_name, NULL, &sidLength, NULL, &sidLengthDomain, &sidType);
                    PSID sidValue = (PSID)new BYTE[sidLength];
                    LPTSTR wszDomainName = new WCHAR[sidLengthDomain];
                    if (!LookupAccountNamePtr(NULL, pTmpBuf->grpi1_name, sidValue, &sidLength, wszDomainName, &sidLengthDomain, &sidType))
                    {
                        free(sidValue);
                        free(wszDomainName);
                        wprintf(L"#\t\tError convert name to SID\n\n");
                        continue;
                    }
                    //распечатываем SID
                    if (ConvertSidToStringSidPtr(sidValue, &sStringSid))
                    {
                        wprintf(L"#\tSID: \n#\t\t%s\n", sStringSid);
                    }

                    //получаем привилегии
                    LSA_HANDLE policyHandle = GetPolicyHandle();
                    PLSA_UNICODE_STRING privUser = NULL;
                    ULONG countOfRights = 0;
                    NTSTATUS stat = 0;
                    stat = LsaEnumerateAccountRightsPtr(policyHandle, sidValue, &privUser, &countOfRights);
                    ULONG status = 0;
                    //распечатываем привилегии
                    wprintf(L"#\tPrivileges:\n");
                    if (status = LsaNtStatusToWinErrorPtr(stat) != ERROR_SUCCESS)
                    {
                        wprintf(L"\n");
                    }
                    else
                    {
                        for (int i = 0; i < countOfRights; i++)
                        {
                            wprintf(L"#\t\t%s\n", privUser->Buffer);
                            privUser++;
                        }
                        wprintf(L"\n");
                    }
                    LsaClose(policyHandle);
                    LocalFree(sStringSid);
                    pTmpBuf++;
                }
            }
        }
        else
        {
            fprintf(stderr, "A system error has occurred: %d\n", status);
        }
        //освобождаем выделенную память, если выделялась
        if (pBuf != NULL)
        {
            NetApiBufferFreePtr(pBuf);
            pBuf = NULL;
        }
    } while (status == ERROR_MORE_DATA);

    //освобождаем выделенную память, если выделялась
    if (pBuf != NULL)
    {
        NetApiBufferFreePtr(pBuf);
    }
    return;
}