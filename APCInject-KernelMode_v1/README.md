# APCInject-KernelMode_v1
APCInject-KernelMode_v1
pnputil -d oem11.inf
delete istalled inf
sc create APCInjectDriver type= kernel start= demand error= normal binPath= "C:\Windows\System32\drivers\APCInject-DriverMode.sys" DisplayName= "APC Injection Kernel Driver"
if start server failed, run this command line to create server
