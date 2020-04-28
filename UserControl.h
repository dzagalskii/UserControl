#pragma once

//получить дескриптор объекта Policy (LSA_HANDLE)
LSA_HANDLE GetPolicyHandle(void);
//перечислить привилегии 
void Enumerate_Privileges(LPTSTR _user_name);
//получить SID пользовател€ по имени
void Get_User_Sid(LPTSTR _user_name);
//перечислить пользователей
void Enumerate_Users(LPTSTR _server_name);
//перечислить группы указанного пользовател€
void Enumerate_Groups(LPWSTR _user_name);
//перечислить все группы в системе
void Get_Groups_Enum(void);
//распечатать привилегии пользовател€ или группы
void printPrivileges(LPWSTR lpszUser);
//просто перечисление привилегий с индексами
void List_Privileges(void);

//добавить пользовател€
int Add_User(LPWSTR lpszUser, LPWSTR lpszPassword);
//удалить пользовател€
int Delete_User(LPWSTR lpszUser);
//установить привилегии дл€ пользовател€(группы)
int Set_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
//удалить привилегию пользовател€(группы)
int Clear_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
//удалить все привилегии пользовател€(группы)
int Clear_All_User_Privileges(LPWSTR lpszUser);
//добавить пользовател€ в группу
int Assign_User_To_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);
//удалить пользовател€ из группы
int Exclude_User_From_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);
//добавить группу
int Add_Group(LPWSTR lpszLocalGroup);
//удалить группу
int Delete_Group(LPWSTR lpszLocalGroup);