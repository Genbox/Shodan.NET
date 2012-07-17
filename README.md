## Introduction

The Shodan.NET class library build in .net 4.0 C#, provides a class to search, getting host information, exploits from ExploitDB and more.

## Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

Setup the SHODAN client:
```csharp
using ShodanNET;

Shodan shodan = new Shodan("YOUR API KEY");
```

Print a list of cisco-ios devices:
```csharp
List<Host> hosts = shodan.Search("cisco-ios");

foreach (Host h in hosts)
{
	Console.WriteLine(h.IP.ToString());
}
```

Get all the information SHODAN has on the IP 217.140.75.46:
```csharp
Host host = shodan.GetHost("217.140.75.46");
Console.WriteLine(host.IP.ToString());
```

Search for exploits on ExploitDB and modules on MSF:
```csharp
List<Exploit> exploits = shodan.SearchExploits("Microsoft Windows XP");

foreach (Exploit exploit in exploits)
{
	Console.WriteLine(exploit.Description);
}

List<MSFModule> modules = shodan.SearchMSFModules("Oracle");

foreach (MSFModule msfModule in modules)
{
	Console.WriteLine(msfModule.Name);
}
```

Download exploit from ExploitDB and modules from MSF:
```csharp
DataResponse exploitData = shodan.DownloadExploit(17133);
Console.WriteLine(exploitData.Filename);

//Note that we also write the file to disk
DataResponse module = shodan.DownloadMSFModule("exploit/windows/browser/ms06_055_vml_method");
module.WriteToFile("C:\\" + module.Filename);
Console.WriteLine(module.Filename);
```