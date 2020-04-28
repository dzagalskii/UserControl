#pragma once

//�������� ���������� ������� Policy (LSA_HANDLE)
LSA_HANDLE GetPolicyHandle(void);
//����������� ���������� 
void Enumerate_Privileges(LPTSTR _user_name);
//�������� SID ������������ �� �����
void Get_User_Sid(LPTSTR _user_name);
//����������� �������������
void Enumerate_Users(LPTSTR _server_name);
//����������� ������ ���������� ������������
void Enumerate_Groups(LPWSTR _user_name);
//����������� ��� ������ � �������
void Get_Groups_Enum(void);
//����������� ���������� ������������ ��� ������
void printPrivileges(LPWSTR lpszUser);
//������ ������������ ���������� � ���������
void List_Privileges(void);

//�������� ������������
int Add_User(LPWSTR lpszUser, LPWSTR lpszPassword);
//������� ������������
int Delete_User(LPWSTR lpszUser);
//���������� ���������� ��� ������������(������)
int Set_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
//������� ���������� ������������(������)
int Clear_User_Privileges(LPWSTR lpszUser, DWORD _privilege_index);
//������� ��� ���������� ������������(������)
int Clear_All_User_Privileges(LPWSTR lpszUser);
//�������� ������������ � ������
int Assign_User_To_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);
//������� ������������ �� ������
int Exclude_User_From_Group(LPWSTR lpszUser, LPWSTR lpszLocalGroup);
//�������� ������
int Add_Group(LPWSTR lpszLocalGroup);
//������� ������
int Delete_Group(LPWSTR lpszLocalGroup);